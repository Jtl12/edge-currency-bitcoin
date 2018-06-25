// @flow
import type { EdgeSpendTarget } from 'edge-core-js'
import type { UtxoInfo, AddressInfo, AddressInfos } from './engineState.js'
import bcoin from 'bcoin'
import { FormatSelector } from '../utils/formatSelector.js'
import { parsePath, getPrivateFromSeed } from '../utils/coinUtils.js'
import {
  toLegacyFormat,
  toNewFormat
} from '../utils/addressFormat/addressFormatIndex.js'

const GAP_LIMIT = 10
const RBF_SEQUENCE_NUM = 0xffffffff - 2
const nop = () => {}

export type Txid = string
export type RawTx = string
export type BlockHeight = number

export type Address = {
  displayAddress: string,
  scriptHash: string,
  index: number,
  branch: number
}

export type KeyRing = {
  pubKey: any,
  privKey: any,
  children: Array<Address>
}

export type Keys = {
  master: KeyRing,
  receive: KeyRing,
  change: KeyRing
}

export type RawKey = string

export type RawKeyRing = {
  xpriv?: RawKey,
  xpub?: string
}

export type RawKeys = {
  master?: RawKeyRing,
  receive?: RawKeyRing,
  change?: RawKeyRing
}

export type createTxOptions = {
  outputs: Array<EdgeSpendTarget>,
  utxos: Array<{
    utxo: UtxoInfo,
    tx: any,
    height: BlockHeight
  }>,
  height: BlockHeight,
  rate: number,
  maxFee: number,
  subtractFee?: boolean,
  setRBF?: boolean,
  RBFraw?: RawTx,
  CPFP?: Txid,
  CPFPlimit?: number
}

export interface KeyManagerCallbacks {
  // When deriving new address send it to caching and subscribing
  +onNewAddress?: (scriptHash: string, address: string, path: string) => void;
  // When deriving new key send it to caching
  +onNewKey?: (keys: any) => void;
}

export type KeyManagerOptions = {
  account?: number,
  bip?: string,
  coinType?: number,
  rawKeys?: RawKeys,
  seed?: string,
  gapLimit: number,
  network: string,
  callbacks: KeyManagerCallbacks,
  addressInfos?: AddressInfos,
  txInfos?: { [txid: string]: any }
}

export class KeyManager {
  masterPath: string
  currencyName: string
  writeLock: any
  bip: string
  keys: Keys
  seed: string
  gapLimit: number
  network: string
  fSelector: any
  onNewAddress: (scriptHash: string, address: string, path: string) => void
  onNewKey: (keys: any) => void
  addressInfos: AddressInfos
  txInfos: { [txid: string]: any }

  constructor ({
    account = 0,
    bip = 'bip32',
    coinType = -1,
    rawKeys = {},
    seed = '',
    gapLimit = GAP_LIMIT,
    network,
    callbacks,
    addressInfos = {},
    txInfos = {}
  }: KeyManagerOptions) {
    // Check for any way to init the wallet with either a seed or master keys
    if (
      seed === '' &&
      (!rawKeys.master || (!rawKeys.master.xpriv && !rawKeys.master.xpub))
    ) {
      throw new Error('Missing Master Key')
    }
    this.seed = seed
    this.gapLimit = gapLimit
    this.network = network
    this.bip = bip
    this.fSelector = FormatSelector(bip, network)
    // Create a lock for when deriving addresses
    this.writeLock = new bcoin.utils.Lock()
    // Create the master derivation path
    this.masterPath = this.fSelector.createMasterPath(account, coinType)
    // Set the callbacks with nops as default
    const { onNewAddress = nop, onNewKey = nop } = callbacks
    this.onNewAddress = onNewAddress
    this.onNewKey = onNewKey
    // Set the addresses and txs state objects
    this.addressInfos = addressInfos
    this.txInfos = txInfos
    // Create KeyRings while tring to load as many of the pubKey/privKey from the cache
    this.keys = this.fSelector.keysFromRaw(rawKeys)
    // Load addresses from Cache
    for (const scriptHash in addressInfos) {
      const addressObj: AddressInfo = addressInfos[scriptHash]
      const path = parsePath(addressObj.path, this.masterPath)
      if (path.length) {
        const [branch, index] = path
        const displayAddress = toNewFormat(addressObj.displayAddress, network)
        const address = { displayAddress, scriptHash, index, branch }
        if (branch === 0) {
          this.keys.receive.children.push(address)
        } else {
          this.keys.change.children.push(address)
        }
      }
    }
    // Cache is not sorted so sort addresses according to derivation index
    this.keys.receive.children.sort((a, b) => a.index - b.index)
    this.keys.change.children.sort((a, b) => a.index - b.index)
  }

  // ////////////////////////////////////////////// //
  // /////////////// Public API /////////////////// //
  // ////////////////////////////////////////////// //
  async load () {
    // If we don't have a public master key we will now create it from seed
    if (!this.keys.master.pubKey) await this.initMasterKeys()
    await this.setLookAhead(true)
  }

  async reload () {
    for (const branch in this.keys) {
      this.keys[branch].children = []
    }
    await this.load()
  }

  getReceiveAddress (): string {
    return this.getNextAvailable(this.keys.receive.children)
  }

  getChangeAddress (): string {
    if (this.bip === 'bip32') return this.getReceiveAddress()
    return this.getNextAvailable(this.keys.change.children)
  }

  async createTX ({
    outputs,
    utxos,
    height,
    rate,
    maxFee,
    subtractFee = false,
    setRBF = false,
    RBFraw = '',
    CPFP = '',
    CPFPlimit = 1
  }: createTxOptions): any {
    // If it's not a CPFP transaction it has to have outputs
    // CPFP transactions can receive an empty outputs array
    if (outputs.length === 0 && CPFP !== '') {
      throw new Error('No outputs available.')
    }

    // If it's not a CPFP transaction it has to have outputs
    const mtx = new bcoin.primitives.MTX()
    // Add the outputs
    for (const spendTarget of outputs) {
      if (!spendTarget.publicAddress || !spendTarget.nativeAmount) continue
      if (typeof spendTarget.publicAddress !== 'string') {
        // $FlowFixMe
        spendTarget.publicAddress = spendTarget.publicAddress.toString()
      }
      const value = parseInt(spendTarget.nativeAmount)
      const legacyAddress = toLegacyFormat(
        // $FlowFixMe
        spendTarget.publicAddress,
        this.network
      )
      const script = bcoin.script.fromAddress(legacyAddress)
      mtx.addOutput(script, value)
    }

    // Get the Change Address
    const changeAddress = toLegacyFormat(this.getChangeAddress(), this.network)

    if (CPFP) {
      utxos = utxos.filter(({ utxo }) => utxo.txid === CPFP)
      // If not outputs are given try and build the most efficient TX
      if (!mtx.outputs || mtx.outputs.length === 0) {
        // Sort the UTXOs by size
        utxos = utxos.sort(
          (a, b) => parseInt(b.utxo.value) - parseInt(a.utxo.value)
        )
        // Try and get only the biggest UTXO unless the limit is 0 which means take all
        if (CPFPlimit) utxos = utxos.slice(0, CPFPlimit)
        // CPFP transactions will try to not have change
        // by subtracting moving all the value from the UTXOs
        // and subtracting the fee from the total output value
        const value = utxos.reduce((s, { utxo }) => s + utxo.value, 0)
        subtractFee = true
        // CPFP transactions will add the change address as a single output
        const script = bcoin.script.fromAddress(changeAddress)
        mtx.addOutput(script, value)
      }
    }

    const coins = utxos.map(({ tx, utxo, height }) => {
      return bcoin.primitives.Coin.fromTX(tx, utxo.index, height)
    })

    await mtx.fund(coins, {
      selection: 'value',
      changeAddress: changeAddress,
      subtractFee: subtractFee,
      height: height,
      rate: rate,
      maxFee: maxFee,
      estimate: prev => this.fSelector.estimateSize(prev)
    })

    // If TX is RBF mark is by changing the Inputs sequences
    if (setRBF) {
      for (const input of mtx.inputs) {
        input.sequence = RBF_SEQUENCE_NUM
      }
    }

    // Check consensus rules for fees and outputs
    if (!mtx.isSane()) {
      throw new Error('TX failed sanity check.')
    }

    // Check consensus rules for inputs
    if (!mtx.verifyInputs(height)) {
      throw new Error('TX failed context check.')
    }

    return mtx
  }

  async sign (mtx: any, privateKeys: Array<string> = []) {
    const keyRings = []
    for (const key of privateKeys) {
      const privKey = bcoin.primitives.KeyRing.fromSecret(key, this.network)
      keyRings.push(privKey)
    }
    if (!keyRings.length) {
      if (!this.keys.master.privKey && this.seed === '') {
        throw new Error("Can't sign without private key")
      }
      await this.initMasterKeys()
      for (const input: any of mtx.inputs) {
        const { prevout } = input
        if (prevout) {
          const [branch: number, index: number] = this.utxoToPath(prevout)
          const keyRing = branch === 0 ? this.keys.receive : this.keys.change
          if (!keyRing.privKey) {
            keyRing.privKey = await this.keys.master.privKey.derive(branch)
            this.saveKeysToCache()
          }
          const key = await this.fSelector.deriveKeyRing(keyRing.privKey, index)
          keyRings.push(key)
        }
      }
    }
    await mtx.template(keyRings)
    mtx.sign(keyRings, bcoin.networks[this.network].replayProtaction)
  }

  getSeed (): string | null {
    if (this.seed && this.seed !== '') {
      try {
        return this.fSelector.parseSeed(this.seed)
      } catch (e) {
        console.log(e)
        return null
      }
    }
    return null
  }

  getPublicSeed (): string | null {
    return this.keys.master.pubKey
      ? this.keys.master.pubKey.toBase58(this.network)
      : null
  }

  // ////////////////////////////////////////////// //
  // ////////////// Private API /////////////////// //
  // ////////////////////////////////////////////// //

  utxoToPath (prevout: any): Array<number> {
    const parsedTx = this.txInfos[prevout.rhash()]
    if (!parsedTx) throw new Error('UTXO not synced yet')
    const output = parsedTx.outputs[prevout.index]
    if (!output) throw new Error('Corrupt UTXO or output list')
    const scriptHash = output.scriptHash
    const address = this.addressInfos[scriptHash]
    if (!address) throw new Error('Address is not part of this wallet')
    const path = address.path
    const pathSuffix = path.split(this.masterPath + '/')[1]
    const [branch, index] = pathSuffix.split('/')
    return [parseInt(branch), parseInt(index)]
  }

  getNextAvailable (addresses: Array<Address>): string {
    let key = null
    for (let i = 0; i < addresses.length; i++) {
      const scriptHash = addresses[i].scriptHash
      if (
        this.addressInfos[scriptHash] &&
        !this.addressInfos[scriptHash].used
      ) {
        key = addresses[i]
        break
      }
    }
    return key
      ? key.displayAddress
      : addresses[addresses.length - 1].displayAddress
  }

  async initMasterKeys () {
    if (this.keys.master.privKey) {
      this.keys.master.pubKey = this.keys.master.privKey.toPublic()
    } else {
      const privateKey = await getPrivateFromSeed(this.seed, this.network)
      const privKey = await privateKey.derivePath(this.masterPath)
      const pubKey = privKey.toPublic()
      this.keys.master = { ...this.keys.master, privKey, pubKey }
    }
    return this.saveKeysToCache()
  }

  saveKeysToCache () {
    try {
      const keys = {}
      for (const type in this.keys) {
        keys[type] = {}
        if (this.keys[type].privKey) {
          keys[type].xpriv = this.keys[type].privKey.toBase58(this.network)
        }
        if (this.keys[type].pubKey) {
          keys[type].xpub = this.keys[type].pubKey.toBase58(this.network)
        }
      }
      this.onNewKey(keys)
    } catch (e) {
      console.log(e)
    }
  }

  async setLookAhead (closeGaps: boolean = false) {
    const unlock = await this.writeLock.lock()
    try {
      const { branches } = this.fSelector
      for (let i = 0; i < branches.length; i++) {
        await this.deriveNewKeys(this.keys[branches[i]], i, closeGaps)
      }
    } catch (e) {
      console.log(e)
    } finally {
      unlock()
    }
  }

  async deriveNewKeys (keyRing: KeyRing, branch: number, closeGaps: boolean) {
    const { children } = keyRing
    // If we never derived a public key for this branch before
    if (!keyRing.pubKey) {
      keyRing.pubKey = await this.keys.master.pubKey.derive(branch)
      this.saveKeysToCache()
    }

    // If the chain might have gaps, fill those in:
    if (closeGaps) {
      let index = 0
      const length = children.length
      for (let i = 0; i < length; ++i, ++index) {
        while (index < children[i].index) {
          await this.updateKeyRing(keyRing, branch, index++)
        }
      }
      if (children.length > length) {
        // New addresses get appended, so sort them back into position:
        children.sort((a, b) => a.index - b.index)
      }
    }

    // Find the last used address:
    let lastUsed =
      children.length < this.gapLimit ? 0 : children.length - this.gapLimit
    for (let i = lastUsed; i < children.length; ++i) {
      const scriptHash = children[i].scriptHash
      if (this.addressInfos[scriptHash] && this.addressInfos[scriptHash].used) {
        lastUsed = i
      }
    }

    // If the last used address is too close to the end, generate some more:
    while (lastUsed + this.gapLimit > children.length) {
      await this.updateKeyRing(keyRing, branch, children.length)
    }
  }

  /**
   * Derives an address at the specified branch and index from the keyRing,
   * and adds it to the state.
   * @param keyRing The KeyRing corresponding to the selected branch.
   */
  async updateKeyRing (keyRing: KeyRing, branch: number, index: number) {
    const { address, scriptHash } = await this.fSelector.deriveAddress(
      keyRing.pubKey,
      index
    )
    const displayAddress = toNewFormat(address, this.network)
    const keyPath = `${this.masterPath}/${branch}/${index}`
    keyRing.children.push({ displayAddress, scriptHash, index, branch })
    this.onNewAddress(scriptHash, displayAddress, keyPath)
  }
}
