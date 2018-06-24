// @flow
import type { EdgeCurrencyInfo } from 'edge-core-js'
import { imageServerUrl } from './constants.js'

export const zcoinInfo: EdgeCurrencyInfo = {
  // Basic currency information:
  currencyCode: 'XZC',
  currencyName: 'Zcoin',
  pluginName: 'zcoin',
  denominations: [
    { name: 'XZC', multiplier: '100000000', symbol: 'Z' },
    { name: 'mXZC', multiplier: '100000', symbol: 'mZ' }
  ],
  walletTypes: ['wallet:zcoin', 'wallet:zcoin-bip44'],

  // Configuration options:
  defaultSettings: {
    forks: [],
    network: {
      type: 'zcoin',
      magic: 0xd9b4bef9,
      keyPrefix: {
        privkey: 0xd2,
        xpubkey: 0x0488b21e,
        xprivkey: 0x0488ade4,
        xpubkey58: 'xpub',
        xprivkey58: 'xprv',
        coinType: 136
      },
      addressPrefix: {
        pubkeyhash: 0x52,
        scripthash: 0x7,
        witnesspubkeyhash: null,
        witnessscripthash: null,
        bech32: null
      }
    },
    customFeeSettings: ['satPerByte'],
    gapLimit: 10,
    maxFee: 1000000,
    defaultFee: 1000,
    feeUpdateInterval: 60000,
    feeInfoServer: '',
    infoServer: '',
    simpleFeeSettings: {
      highFee: '150',
      lowFee: '20',
      standardFeeLow: '50',
      standardFeeHigh: '100',
      standardFeeLowAmount: '173200',
      standardFeeHighAmount: '8670000'
    },
    electrumServers: [
      'electrum://51.15.82.184:50001',
      'electrum://45.63.92.224:50001',
      'electrum://47.75.76.176:50001',
      'electrums://51.15.82.184:50002',
      'electrums://45.63.92.224:50002',
      'electrums://47.75.76.176:50002'
    ]
  },
  metaTokens: [],

  // Explorers:
  addressExplorer: 'https://insight.zcoin.io/address/%s',
  blockExplorer: 'https://insight.zcoin.io/block/%s',
  transactionExplorer: 'https://insight.zcoin.io/tx/%s',

  // Images:
  symbolImage: `${imageServerUrl}/zcoin-logo-color-64.png`,
  symbolImageDarkMono: `${imageServerUrl}/zcoin-logo-grey-64.png`
}
