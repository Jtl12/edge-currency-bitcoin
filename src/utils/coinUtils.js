// @flow
import bcoin from 'bcoin'
import { hash256, hash256Sync, reverseBufferToHex } from './utils.js'

export const keysFromWalletInfo = (
  network: string,
  { keys, type }: any = {},
  cachedRawKeys: any = {}
) => {
  const legacyBip = typeof type === 'string' ? type.split('-')[1] : ''
  if (keys) {
    const {
      master: { xpub = keys[`${network}Xpub`], ...rest } = {}
    } = cachedRawKeys
    return {
      rawKeys: { ...cachedRawKeys, master: { ...rest, xpub } },
      seed: keys[`${network}Key`] || '',
      coinType: typeof keys.coinType === 'number' ? keys.coinType : -1,
      bip: typeof keys.format === 'string' ? keys.format : legacyBip
    }
  }
  return { rawKeys: cachedRawKeys, seed: '', coinType: -1, bip: legacyBip }
}

export const keysFromRaw = (rawKeys: any = {}, network: string) => {
  const branches = ['master', 'receive', 'change']
  return branches.reduce((keyRings, branch) => {
    const { xpub, xpriv } = rawKeys[branch] || {}
    return Object.assign(keyRings, {
      [branch]: {
        pubKey: xpub ? bcoin.hd.PublicKey.fromBase58(xpub, network) : null,
        privKey: xpriv ? bcoin.hd.PrivateKey.fromBase58(xpriv, network) : null,
        children: []
      }
    })
  }, {})
}

export const createMasterPath = (
  account: number,
  coinType: number,
  bip: string,
  network: string
) => {
  if (coinType < 0) {
    coinType = bcoin.network.get(network).keyPrefix.coinType
  }
  switch (bip) {
    case 'bip32':
      return 'm/0'
    case 'bip44':
      return `m/44'/${coinType}'/${account}'`
    case 'bip49':
      return `m/49'/${coinType}'/${account}'`
    case 'bip84':
      return `m/84'/${coinType}'/${account}'`
    default:
      throw new Error('Unknown bip type')
  }
}

export const deriveAddress = async (
  parentKey: any,
  index: number,
  bip: string,
  network: string
) => {
  const key = await deriveKeyRing(parentKey, index, bip, network)
  const address = key.getAddress('base58')
  const scriptHash = await addressToScriptHash(address)
  return { address, scriptHash }
}

export const deriveKeyRing = async (
  parentKey: any,
  index: number,
  bip: string,
  network: string
) => {
  const derivedKey = await parentKey.derive(index)
  const options = {
    nested: bip === 'bip49',
    witness: bip === 'bip49',
    ...derivedKey
  }
  const key = bcoin.primitives.KeyRing.fromOptions(options)
  key.network = bcoin.network.get(network)
  return key
}

export const getAllAddresses = async (
  privateKeys: Array<any>,
  network: string
) => {
  const addresses = []
  for (const key of privateKeys) {
    // P2PKH address
    const privKey = bcoin.primitives.KeyRing.fromSecret(key, network)
    const keyAddress = privKey.getAddress('base58')
    const keyHash = await addressToScriptHash(keyAddress)
    addresses.push([keyHash, keyAddress])

    // P2WPKH-nested-in-P2SH address
    privKey.nested = true
    privKey.witness = true
    const nestedAddress = privKey.getAddress('base58')
    const nestedHash = await addressToScriptHash(nestedAddress)
    addresses.push([nestedHash, nestedAddress])
  }
  return addresses
}

export const estimateSize = (prev: any, bip: string) => {
  const scale = bcoin.consensus.WITNESS_SCALE_FACTOR
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
      size = ((size + scale - 1) / scale) | 0
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

export const getPrivateFromSeed = async (seed: string, network: string) => {
  let privateKey
  try {
    const mnemonic = bcoin.hd.Mnemonic.fromPhrase(seed)
    privateKey = await bcoin.hd.PrivateKey.fromMnemonic(mnemonic, network)
  } catch (e) {
    // Legacy type seed from Airbitz
    const keyBuffer = Buffer.from(seed, 'base64')
    privateKey = bcoin.hd.PrivateKey.fromSeed(keyBuffer, network)
  }
  return privateKey
}

export const addressToScriptHash = async (address: string) => {
  const scriptRaw = bcoin.script.fromAddress(address).toRaw()
  const scriptHashRaw = await hash256(scriptRaw)
  const scriptHash: string = reverseBufferToHex(scriptHashRaw)
  return scriptHash
}

export const verifyTx = (rawTx: string, bcoinTx: any) => {
  const tx = bcoinTx || bcoin.primitives.TX.fromRaw(rawTx, 'hex')
  for (const output of tx.outputs) {
    if (output.value <= 0 || output.value === '0') {
      throw new Error('Wrong spend amount')
    }
  }
  return tx
}

export const parsePath = (path: string, masterPath: string) => {
  const pathSuffix = path.split(masterPath + '/')[1]
  if (pathSuffix) {
    const [branch, index] = pathSuffix.split('/')
    return [parseInt(branch), parseInt(index)]
  }
  return []
}

export function parseTransaction (rawTx: string) {
  const bcoinTransaction = bcoin.primitives.TX.fromRaw(rawTx, 'hex')

  for (const output of bcoinTransaction.outputs) {
    const scriptHash = hash256Sync(output.script.toRaw())
    output.scriptHash = reverseBufferToHex(scriptHash)
  }

  return bcoinTransaction
}
