// @flow
// $FlowFixMe
import buffer from 'buffer-hack'
import { hd, primitives, script, network as Network } from 'bcoin'
import { hash256, hash256Sync, reverseBufferToHex } from './utils.js'

// $FlowFixMe
const { Buffer } = buffer

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

export const setKeyType = (
  key: any,
  nested: boolean,
  witness: boolean,
  network: string
): Promise<any> => Promise
  .resolve(primitives.KeyRing.fromOptions({ ...key, nested, witness }))
  .then(clone => Object.assign(clone, { network: Network.get(network) }))

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

export const parseTransaction = (
  rawTx: string,
  bcoinTx: any = primitives.TX.fromRaw(rawTx, 'hex')
) => !bcoinTx.outputs.forEach(output => {
  output.scriptHash = reverseBufferToHex(hash256Sync(output.script.toRaw()))
}) && bcoinTx

export const parsePath = (
  path: string = '', masterPath: string
) => (path.split(`${masterPath}`)[1] || '')
  .split('/')
  .filter(i => i !== '')
  .map(i => parseInt(i))
