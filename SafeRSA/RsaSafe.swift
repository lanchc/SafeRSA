//
//  RsaSafe.swift
//  iHello
//
//  Created by 吴非 on 2022/7/15.
//

import Foundation
import CommonCrypto

// 加密操作
public struct RsaSafe {
    
    // MARK: - 公钥 加密&解密
    public static func decryption(_ cipherText: String, puk: String) -> String? {
        guard let rData = SkySafe.base64_decode(cipherText) else { return nil }
        guard let secKey = SkySafe.addRSAPublicKey(puk) else { return nil }
        guard let eData = rk_decrypt(rData, with: secKey, padding: SecPadding()) else { return nil }
        return String(data: eData, encoding: String.Encoding.utf8)
    }
    
    public static func encryption(_ masterText: String, puk: String) -> String? {
        guard let rData = masterText.data(using: String.Encoding.utf8) else { return nil }
        guard let secKey = SkySafe.addRSAPublicKey(puk) else { return nil }
        return rk_encrypt(rData, with: secKey, and: false, padding: .PKCS1)?.base64EncodedString()
    }
    
    // MARK: - 私钥 加密&解密
    public static func decryption(_ cipherText: String, prk: String) -> String? {
        guard let rData = SkySafe.base64_decode(cipherText) else { return nil }
        guard let secKey = SkySafe.addRSAPrivateKey(prk) else { return nil }
        guard let eData = rk_decrypt(rData, with: secKey, padding: SecPadding()) else { return nil }
        return String(data: eData, encoding: String.Encoding.utf8)
    }
    
    public static func encryption(_ masterText: String, prk: String) -> String? {
        guard let rData = masterText.data(using: String.Encoding.utf8) else { return nil }
        guard let secKey = SkySafe.addRSAPrivateKey(prk) else { return nil }
        return rk_encrypt(rData, with: secKey, and: true, padding: .PKCS1)?.base64EncodedString()
    }
    
    // 数据验证
    public static func isVerification(_ cipherText: String, sign: String, puk: String) -> Bool {
        guard let pukRef = SkySafe.addRSAPublicKey(puk) else { return false }
        guard let mstrData = SkySafe.formatBySha1(targetData: cipherText.data(using: .utf8)) else { return false }
        guard let signData = NSData(base64Encoded: sign, options: .ignoreUnknownCharacters) else { return false }
        
        if #available(iOS 15.0, *) {
            return SecKeyVerifySignature(pukRef, .rsaSignatureDigestPKCS1v15SHA1, mstrData, signData, nil)
        } else {
            return SecKeyRawVerify(pukRef, .PKCS1SHA1, mstrData.bytes, mstrData.length, signData.bytes, signData.length) == errSecSuccess
        }
    }
    
}


extension RsaSafe {
    
    // 解密操作
    fileprivate static func rk_decrypt(_ data: Data, with secKey: SecKey, padding: SecPadding) -> Data? {
        let blockSize = SecKeyGetBlockSize(secKey)
        
        var encryptedDataAsArray = [UInt8](repeating: 0, count: data.count / MemoryLayout<UInt8>.size)
        (data as NSData).getBytes(&encryptedDataAsArray, length: data.count)
        
        var decryptedData = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while (idx < encryptedDataAsArray.count ) {
            var idxEnd = idx + blockSize
            if ( idxEnd > encryptedDataAsArray.count ) {
                idxEnd = encryptedDataAsArray.count
            }
            var chunkData = [UInt8](repeating: 0, count: blockSize)
            for i in idx..<idxEnd {
                chunkData[i-idx] = encryptedDataAsArray[i]
            }
            
            var decryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
            var decryptedDataLength = blockSize
            
            let status = SecKeyDecrypt(secKey, padding, chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
            if ( status != noErr ) {
                return nil
            }
            let finalData = removePadding(decryptedDataBuffer)
            decryptedData += finalData
            
            idx += blockSize
        }
        return Data(bytes: decryptedData, count: decryptedData.count)
    }
    
    fileprivate static func removePadding(_ data: [UInt8]) -> [UInt8] {
        var idxFirstZero = -1
        var idxNextZero = data.count
        for i in 0..<data.count {
            if ( data[i] == 0 ) {
                if ( idxFirstZero < 0 ) {
                    idxFirstZero = i
                } else {
                    idxNextZero = i
                    break
                }
            }
        }
        var newData = [UInt8](repeating: 0, count: idxNextZero-idxFirstZero-1)
        for i in idxFirstZero+1..<idxNextZero {
            newData[i-idxFirstZero-1] = data[i]
        }
        return newData
    }
    
    // 加密操作
    fileprivate static func rk_encrypt(_ data: Data, with secKey: SecKey, and isSign: Bool, padding: SecPadding) -> Data? {
        
        let blockSize = SecKeyGetBlockSize(secKey)
        
        var maxChunkSize: Int
        switch padding {
        case []:
            maxChunkSize = blockSize
        case .OAEP:
            maxChunkSize = blockSize - 42
        default:
            maxChunkSize = blockSize - 11
        }
        
        var decryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&decryptedDataAsArray, length: data.count)
        
        var encryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < decryptedDataAsArray.count {
            
            let idxEnd = min(idx + maxChunkSize, decryptedDataAsArray.count)
            let chunkData = [UInt8](decryptedDataAsArray[idx..<idxEnd])
            
            var encryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
            var encryptedDataLength = blockSize
            
            
            var status = noErr
            
            if isSign {
                status = SecKeyRawSign(secKey, padding, chunkData, chunkData.count, &encryptedDataBuffer, &encryptedDataLength)
            } else {
                status = SecKeyEncrypt(secKey, padding, chunkData, chunkData.count, &encryptedDataBuffer, &encryptedDataLength)
            }
            
            guard status == noErr else { return nil }
            
            encryptedDataBytes += encryptedDataBuffer
            
            idx += maxChunkSize
        }
        
        return Data(bytes: encryptedDataBytes, count: encryptedDataBytes.count)
    }
}
