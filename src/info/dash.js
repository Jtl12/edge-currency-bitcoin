// @flow
import type { EdgeCurrencyInfo } from 'edge-core-js'
import { imageServerUrl } from './constants.js'

export const dashInfo: EdgeCurrencyInfo = {
  // Basic currency information:
  currencyCode: 'DASH',
  currencyName: 'Dash',
  pluginName: 'dash',
  denominations: [
    { name: 'DASH', multiplier: '100000000', symbol: 'D' },
    { name: 'mDASH', multiplier: '100000', symbol: 'mD' }
  ],
  walletTypes: ['wallet:dash-bip44', 'wallet:dash'],

  // Configuration options:
  defaultSettings: {
    network: {
      type: 'dash',
      magic: 0xd9b4bef9,
      keyPrefix: {
        privkey: 0xcc,
        xpubkey: 0x02fe52cc,
        xprivkey: 0x02fe52f8,
        xpubkey58: 'xpub',
        xprivkey58: 'xprv',
        coinType: 5
      },
      addressPrefix: {
        pubkeyhash: 0x4c,
        scripthash: 0x10,
        witnesspubkeyhash: null,
        witnessscripthash: null,
        bech32: null
      }
    },
    customFeeSettings: ['satPerByte'],
    gapLimit: 10,
    maxFee: 100000,
    defaultFee: 10000,
    feeUpdateInterval: 60000,
    feeInfoServer: '',
    infoServer: 'https://info1.edgesecure.co:8444/v1',
    simpleFeeSettings: {
      highFee: '300',
      lowFee: '100',
      standardFeeLow: '150',
      standardFeeHigh: '200',
      standardFeeLowAmount: '20000000',
      standardFeeHighAmount: '981000000'
    },
    electrumServers: [
      'electrum://electrum.dash.siampm.com:50001',
      'electrum://e-1.claudioboxx.com:50005',
      'electrum://electrum.leblancnet.us:50015',
      'electrums://e-1.claudioboxx.com:50006',
      'electrums://ele.nummi.it:50008',
      'electrums://178.62.234.69:50002',
      'electrum://178.62.234.69:50001',
      'electrums://electrum.leblancnet.us:50016',
      'electrums://electrum.dash.siampm.com:50002'
    ]
  },
  metaTokens: [],

  // Explorers:
  addressExplorer: 'https://explorer.dash.org/address/%s',
  blockExplorer: 'https://explorer.dash.org/block/%s',
  transactionExplorer: 'https://explorer.dash.org/tx/%s',

  // Images:
  symbolImage:
    `${imageServerUrl}/dash-logo-64.png`,
  symbolImageDarkMono:
    `${imageServerUrl}/dash-logo-grey-64.png`
}
