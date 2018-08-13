const sm = require('../../components/index')

function compareArray(a, b) {
  if (a.length !== b.length) return false

  for (let i = 0, len = a.length; i < a; i++) {
    if (a[i] !== b[i]) return false;
  }

  return true;
}

Page({
  onLoad() {
    this.sm2()
    this.sm3()
    this.sm4()
  },

  sm2() {
    let sm2 = sm.sm2
    let msgString = 'absasdagfadgadsfdfdsf'
    let cipherMode = 1

    let keypair = sm2.generateKeyPairHex()
    let publicKey = keypair.publicKey
    let privateKey = keypair.privateKey
    console.log('sm2 --> generate keypair', publicKey.length === 130 && privateKey.length === 64)

    let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode)
    let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
    console.log('sm2 --> encrypt and decrypt data', decryptData === msgString)
  },

  sm3() {
    let sm3 = sm.sm3

    console.log('sm3 --> test1: ', sm3('abc') === '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
    console.log('sm3 --> test2: ', sm3('abcdefghABCDEFGH12345678') === 'd670c7f027fd5f9f0c163f4bfe98f9003fe597d3f52dbab0885ec2ca8dd23e9b')
    console.log('sm3 --> test3: ', sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefgh') === '1cf3bafec325d7d9102cd67ba46b09195af4e613b6c2b898122363d810308b11')
    console.log('sm3 --> test4: ', sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCD') === 'b8ac4203969bde27434ce667b0adbf3439ee97e416e73cb96f4431f478a531fe')
    console.log('sm3 --> test5: ', sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDEFGH') === '5ef0cdbe0d54426eea7f5c8b44385bb1003548735feaa59137c3dfe608aa9567')
    console.log('sm3 --> test6: ', sm3('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd') === 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')
  },

  sm4() {
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
    let sm4 = sm.sm4

    console.log('sm4 --> encrypt a group: ', compareArray(sm4.encrypt([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10], key), [0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46]))
    
    console.log('sm4 --> decrypt a group: ', compareArray(sm4.decrypt([0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46], key), [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]))

  },
})
