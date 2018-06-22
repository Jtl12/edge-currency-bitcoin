// @flow
import { hd, primitives, script, consensus, network as Network } from 'bcoin'
import { hash256, hash256Sync, reverseBufferToHex } from './utils.js'

const keyToBase58 = (key: any): Promise<any> =>
  Promise
    .resolve(key.getAddress('base58'))
    .then(address => addressToScriptHash(address)
      .then(scriptHash => ({ address, scriptHash })))

const setKeyType = (
  key: any,
  network: string,
  nested: boolean,
  witness: boolean
): Promise<any> => Promise
  .resolve(primitives.KeyRing.fromOptions({ ...key, nested, witness }))
  .then(clone => Object.assign(clone, { network: Network.get(network) }))

const Bips = {
  'bip32': {
    masterPath: (coinType, account) => 'm/0',
    branches: ['master', 'receive', 'change'],
    setKeyType: (key, network) => setKeyType(key, network, false, false),
    getAddress: (key, network) =>
      setKeyType(key, network, false, false).then(key => keyToBase58(key))
  },
  'bip44': {
    masterPath: (coinType, account) => `m/44'/${coinType}'/${account}'`,
    branches: ['master', 'receive', 'change'],
    setKeyType: (key, network) => setKeyType(key, network, false, false),
    getAddress: (key, network) =>
      setKeyType(key, network, false, false).then(key => keyToBase58(key))
  },
  'bip49': {
    masterPath: (coinType, account) => `m/49'/${coinType}'/${account}'`,
    branches: ['master', 'receive', 'change'],
    setKeyType: (key, network) => setKeyType(key, network, true, true),
    getAddress: (key, network) =>
      setKeyType(key, network, true, true).then(key => keyToBase58(key))
  },
  'bip84': {
    masterPath: (coinType, account) => `m/84'/${coinType}'/${account}'`,
    branches: ['master', 'receive', 'change'],
    setKeyType: (key, network) => setKeyType(key, network, false, true),
    getAddress: (key, network) =>
      setKeyType(key, network, false, true).then(key => keyToBase58(key))
  }
}
const witScale = consensus.WITNESS_SCALE_FACTOR

export const keysFromWalletInfo = (
  network: string,
  { keys = {}, type }: any = {}, // walletInfo
  { master = {}, ...otherKeys }: any = {} // cachedRawKeys
) => ({
  seed: keys[`${network}Key`] || '',
  coinType: typeof keys.coinType === 'number' ? keys.coinType : -1,
  rawKeys: {
    ...otherKeys,
    master: {
      ...master,
      xpub: master.xpub || keys[`${network}Xpub`]
    }
  },
  bip: typeof keys.format === 'string'
    ? keys.format
    : typeof type === 'string'
      ? type.split('-')[1]
      : ''
})

export const keysFromRaw = (rawKeys: any = {}, bip: string, network: string) =>
  Bips[bip].branches.reduce((keyRings, branch) => {
    const { xpub, xpriv } = rawKeys[branch] || {}
    return {
      ...keyRings,
      [branch]: {
        pubKey: xpub ? hd.PublicKey.fromBase58(xpub, network) : null,
        privKey: xpriv ? hd.PrivateKey.fromBase58(xpriv, network) : null,
        children: []
      }
    }
  }, {})

export const createMasterPath = (
  account: number,
  coinType: number,
  bip: string,
  network: string
) => !Bips[bip]
  ? null
  : Bips[bip].masterPath(
    coinType >= 0
      ? coinType
      : Network.get(network).keyPrefix.coinType,
    account
  )

export const deriveAddress = (
  parentKey: any,
  index: number,
  bip: string,
  network: string
): Promise<any> => deriveKeyRing(parentKey, index, bip, network)
  .then(key => Bips[bip].getAddress(key, network))

export const deriveKeyRing = (
  parentKey: any,
  index: number,
  bip: string,
  network: string
): Promise<any> => Promise
  .resolve(parentKey.derive(index))
  .then(derivedKey => Bips[bip].setKeyType(derivedKey, network))

export const getPrivateFromSeed = (
  seed: string,
  network: string
) => Promise
  .resolve(hd.Mnemonic.fromPhrase(seed))
  .then(mnemonic =>
    Promise.resolve(hd.PrivateKey.fromMnemonic(mnemonic, network)))
  .catch(e => hd.PrivateKey.fromSeed(Buffer.from(seed, 'base64'), network))

export const addressToScriptHash = (
  address: string
): Promise<string> => Promise
  .resolve(script.fromAddress(address).toRaw())
  .then(scriptRaw => hash256(scriptRaw))
  .then(scriptHashRaw => reverseBufferToHex(scriptHashRaw))

export const verifyTxAmount = (
  rawTx: string,
  bcoinTx: any = primitives.TX.fromRaw(rawTx, 'hex')
) => bcoinTx.outputs.find(({ value }) => parseInt(value) <= 0)
  ? false
  : bcoinTx

export const parsePath = (
  path: string = '', masterPath: string
) => (path.split(`${masterPath}`)[1] || '')
  .split('/')
  .filter(i => i !== '')
  .map(i => parseInt(i))

export const parseTransaction = (
  rawTx: string,
  bcoinTx: any = primitives.TX.fromRaw(rawTx, 'hex')
) => !bcoinTx.outputs.forEach(output => {
  output.scriptHash = reverseBufferToHex(hash256Sync(output.script.toRaw()))
}) && bcoinTx

export const getAllAddresses = async (
  privateKeys: Array<any>,
  network: string
) => Promise.all(Object.keys(Bips).reduce((promises, bip) => [
  ...promises,
  ...privateKeys.map(key =>
    Bips[bip].getAddress(
      primitives.KeyRing.fromSecret(key, network),
      network
    )
  )
], []))

export const estimateSize = (prev: any, bip: string) => {
  const address = prev.getAddress()
  if (!address) return -1

  let size = 0

  if (prev.isScripthash()) {
    if (bip === 'bip49') {
      size += 23 // redeem script
      size *= 4 // vsize
      // Varint witness items length.
      size += 1
      // Calculate vsize
      size = ((size + witScale - 1) / witScale) | 0
    }
  }

  // P2PKH
  if (bip !== 'bip49') {
    // varint script size
    size += 1
    // OP_PUSHDATA0 [signature]
    size += 1 + 73
    // OP_PUSHDATA0 [key]
    size += 1 + 33
  }

  return size || -1
}
