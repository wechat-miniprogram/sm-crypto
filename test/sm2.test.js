const sm2 = require('../src/index').sm2

const cipherMode = 1 // 1 - C1C3C2，0 - C1C2C3

// const msgString = 'abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH';
const msgString = 'absasdagfadgadsfdfdsf'

let publicKey
let privateKey
let compressedPublicKey

beforeAll(() => {
    // 生成密钥对
    let keypair = sm2.generateKeyPairHex()

    publicKey = keypair.publicKey
    privateKey = keypair.privateKey

    compressedPublicKey = sm2.compressPublicKeyHex(publicKey)
})

test('sm2: generate keypair', () => {
    expect(publicKey.length).toBe(130)
    expect(privateKey.length).toBe(64)
    expect(compressedPublicKey.length).toBe(66)
    expect(sm2.verifyPublicKey(publicKey)).toBe(true)
    expect(sm2.verifyPublicKey(compressedPublicKey)).toBe(true)
    expect(sm2.comparePublicKeyHex(publicKey, compressedPublicKey)).toBe(true)

    // 自定义随机数
    const random = []
    for (let i = 0; i < 20; i++) random.push(~~(Math.random() * 10))
    const keypair2 = sm2.generateKeyPairHex(random.join(''))
    expect(keypair2.publicKey.length).toBe(130)
    expect(keypair2.privateKey.length).toBe(64)
    const compressedPublicKey2 = sm2.compressPublicKeyHex(keypair2.publicKey)
    expect(compressedPublicKey2.length).toBe(66)
    expect(sm2.verifyPublicKey(keypair2.publicKey)).toBe(true)
    expect(sm2.verifyPublicKey(compressedPublicKey2)).toBe(true)
    expect(sm2.comparePublicKeyHex(keypair2.publicKey, compressedPublicKey2)).toBe(true)
})

test('sm2: encrypt and decrypt data', () => {
    for (const pK of [publicKey, compressedPublicKey]) {
        let encryptData = sm2.doEncrypt(msgString, pK, cipherMode)
        let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
        expect(decryptData).toBe(msgString)

        for (let i = 0; i < 100; i++) {
            encryptData = sm2.doEncrypt(msgString, pK, cipherMode)
            decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
            expect(decryptData).toBe(msgString)
        }

        encryptData = sm2.doEncrypt([0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66], pK, cipherMode)
        decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
        expect(decryptData).toBe(msgString)
        encryptData = sm2.doEncrypt(Uint8Array.from([0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66]), pK, cipherMode)
        decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
        expect(decryptData).toBe(msgString)
        decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode, {output: 'array'})
        expect(decryptData).toEqual([0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66])
    }
})

test('sm2: sign data and verify sign', () => {
    for (const pK of [publicKey, compressedPublicKey]) {
        // 纯签名 + 生成椭圆曲线点
        let sigValueHex = sm2.doSignature(msgString, privateKey)
        let verifyResult = sm2.doVerifySignature(msgString, sigValueHex, pK)
        expect(verifyResult).toBe(true)
        
        // 纯签名
        let sigValueHex2 = sm2.doSignature(msgString, privateKey, {
            pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()],
        })
        let verifyResult2 = sm2.doVerifySignature(msgString, sigValueHex2, pK);
        expect(verifyResult2).toBe(true)

        // 纯签名 + 生成椭圆曲线点 + der编解码
        let sigValueHex3 = sm2.doSignature(msgString, privateKey, {
            der: true,
        })
        let verifyResult3 = sm2.doVerifySignature(msgString, sigValueHex3, pK, {
            der: true,
        })
        expect(verifyResult3).toBe(true)

        // 纯签名 + 生成椭圆曲线点 + sm3杂凑
        let sigValueHex4 = sm2.doSignature(msgString, privateKey, {
            hash: true,
        })
        let verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, pK, {
            hash: true,
        })
        expect(verifyResult4).toBe(true)
        
        for (let i = 0; i < 100; i++) {
            sigValueHex4 = sm2.doSignature(msgString, privateKey, {
                hash: true,
            })
            verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, pK, {
                hash: true,
            })
            expect(verifyResult4).toBe(true)
        }

        // 纯签名 + 生成椭圆曲线点 + sm3杂凑（不做公钥推导）
        let sigValueHex5 = sm2.doSignature(msgString, privateKey, {
            hash: true,
            pK,
        })
        let verifyResult5 = sm2.doVerifySignature(msgString, sigValueHex5, pK, {
            hash: true,
            pK,
        })
        expect(verifyResult5).toBe(true)

        // 纯签名 + 生成椭圆曲线点 + sm3杂凑 + 不做公钥推 + 添加 userId
        let sigValueHex6 = sm2.doSignature(msgString, privateKey, {
            hash: true,
            pK,
            userId: 'testUserId',
        })
        let verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, pK, {
            hash: true,
            userId: 'testUserId',
        })
        expect(verifyResult6).toBe(true)
        verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, pK, {
            hash: true,
            userId: 'wrongTestUserId',
        })
        expect(verifyResult6).toBe(false)
        sigValueHex6 = sm2.doSignature(msgString, privateKey, {
            hash: true,
            pK,
            userId: '',
        })
        verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, pK, {
            hash: true,
            userId: '',
        })
        expect(verifyResult6).toBe(true)
        verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, pK, {
            hash: true,
        })
        expect(verifyResult6).toBe(false)
        sigValueHex6 = sm2.doSignature(msgString, privateKey, {
            hash: true,
            pK,
        })
        verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, pK, {
            hash: true,
        })
        expect(verifyResult6).toBe(true)
        verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, pK, {
            hash: true,
            userId: '',
        })
        expect(verifyResult6).toBe(false)
        verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, pK, {
            hash: true,
            userId: '1234567812345678'
        })
        expect(verifyResult6).toBe(true)
    }
})
