// @flow
import type { EdgeCurrencyInfo } from 'edge-core-js'
import { imageServerUrl } from './constants.js'

export const litecoinInfo: EdgeCurrencyInfo = {
  // Basic currency information:
  currencyCode: 'LTC',
  currencyName: 'Litecoin',
  pluginName: 'litecoin',
  denominations: [
    { name: 'LTC', multiplier: '100000000', symbol: 'Ł' },
    { name: 'mLTC', multiplier: '100000', symbol: 'mŁ' }
  ],
  walletTypes: [
    'wallet:litecoin-bip49',
    'wallet:litecoin-bip44',
    'wallet:litecoin'
  ],

  // Configuration options:
  defaultSettings: {
    forks: [],
    network: {
      type: 'litecoin',
      magic: 0xd9b4bef9,
      keyPrefix: {
        privkey: 0xb0,
        xpubkey: 0x0488b21e,
        xprivkey: 0x0488ade4,
        xpubkey58: 'xpub',
        xprivkey58: 'xprv',
        coinType: 2
      },
      addressPrefix: {
        pubkeyhash: 0x30,
        scripthash: 0x32,
        legacy: 0x05,
        witnesspubkeyhash: 0x06,
        witnessscripthash: 0x0a,
        bech32: 'lc'
      }
    },
    customFeeSettings: ['satPerByte'],
    gapLimit: 10,
    maxFee: 1000000,
    defaultFee: 50000,
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
      'electrum://electrum-ltc.festivaldelhumor.org:60001',
      'electrum://electrum-ltc.petrkr.net:60001',
      'electrum://electrumx.nmdps.net:9433',
      'electrums://electrum-ltc.festivaldelhumor.org:60002',
      'electrums://electrum-ltc.petrkr.net:60002',
      'electrums://electrum-ltc.villocq.com:60002',
      'electrum://electrum-ltc.villocq.com:60001',
      'electrums://elec.luggs.co:444',
      'electrums://ltc01.knas.systems:50004',
      'electrum://ltc01.knas.systems:50003',
      'electrums://electrum-ltc.wilv.in:50002',
      'electrum://electrum-ltc.wilv.in:50001',
      'electrums://electrum.ltc.xurious.com:50002',
      'electrum://electrum.ltc.xurious.com:50001',
      'electrums://lith.strangled.net:50003',
      'electrums://electrum.leblancnet.us:50004',
      'electrum://electrum.leblancnet.us:50003',
      'electrums://electrum-ltc0.snel.it:50004',
      'electrum://electrum-ltc0.snel.it:50003',
      'electrums://e-2.claudioboxx.com:50004',
      'electrum://e-2.claudioboxx.com:50003',
      'electrums://e-1.claudioboxx.com:50004',
      'electrum://e-1.claudioboxx.com:50003',
      'electrum://node.ispol.sk:50003',
      'electrums://electrum-ltc.bysh.me:50002',
      'electrum://electrum-ltc.bysh.me:50001',
      'electrums://e-3.claudioboxx.com:50004',
      'electrum://e-3.claudioboxx.com:50003',
      'electrums://node.ispol.sk:50004',
      'electrums://electrumx.nmdps.net:9434'
    ]
  },
  metaTokens: [],

  // Explorers:
  addressExplorer: 'https://live.blockcypher.com/ltc/address/%s',
  blockExplorer: 'https://live.blockcypher.com/ltc/block/%s',
  transactionExplorer: 'https://live.blockcypher.com/ltc/tx/%s',

  // Images:
  symbolImage:
    `${imageServerUrl}/litecoin-logo-64.png`,
  symbolImageDarkMono:
    `${imageServerUrl}/litecoin-logo-64.png`
}
