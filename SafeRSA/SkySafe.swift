//
//  SkySafe.swift
//  iHello
//
//  Created by 吴非 on 2022/7/16.
//

import Foundation
import CommonCrypto

struct SkySafe {
    
    static func addRSAPublicKey(_ puk: String, tagName: String = "ChiYu-SkySafe-PUK") -> SecKey? {
        guard let pukTmp = SkySafe.base64_decode(puk) else { return nil }
        return addRSAPublicKey(pubkey: pukTmp, tagName: tagName)
    }
    
    private static func addRSAPublicKey(pubkey: Data, tagName: String) -> SecKey? {
        // Delete any old lingering key with the same tag
        deleteRSAKeyFromKeychain(tagName)
        
        let pubkeyData = stripPublicKeyHeader(pubkey)
        if ( pubkeyData == nil ) {
            return nil
        }
        
        // Add persistent version of the key to system keychain
        //var prt1: Unmanaged<AnyObject>?
        let queryFilter = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : tagName,
            String(kSecValueData)          : pubkeyData!,
            String(kSecAttrKeyClass)       : kSecAttrKeyClassPublic,
            String(kSecReturnPersistentRef): true
            ] as [String : Any]
        let result = SecItemAdd(queryFilter as CFDictionary, nil)
        if ((result != noErr) && (result != errSecDuplicateItem)) {
            return nil
        }
        
        return getRSAKeyFromKeychain(tagName)
    }
    
    static func addRSAPrivateKey(_ prk: String, tagName: String = "ChiYu-SkySafe-PRK") -> SecKey? {
        guard let prkTmp = SkySafe.base64_decode(prk) else { return nil }
        return addRSAPrivateKey(privkey: prkTmp, tagName: tagName)
    }
    
    fileprivate static func addRSAPrivateKey(privkey: Data, tagName: String) -> SecKey? {
        // Delete any old lingering key with the same tag
        deleteRSAKeyFromKeychain(tagName)
        
        let privkeyData = stripPrivateKeyHeader(privkey)
        if ( privkeyData == nil ) {
            return nil
        }
        
        // Add persistent version of the key to system keychain
        // var prt: AnyObject?
        let queryFilter = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : tagName,
            //String(kSecAttrAccessible)     : kSecAttrAccessibleWhenUnlocked,
            String(kSecValueData)          : privkeyData!,
            String(kSecAttrKeyClass)       : kSecAttrKeyClassPrivate,
            String(kSecReturnPersistentRef): true
            ] as [String : Any]
        let result = SecItemAdd(queryFilter as CFDictionary, nil)
        if ((result != noErr) && (result != errSecDuplicateItem)) {
            return nil
        }
        
        return getRSAKeyFromKeychain(tagName)
    }
    
}


// MARK: - keychain
extension SkySafe {
    
    // Delete any existing RSA key from keychain
    fileprivate static func deleteRSAKeyFromKeychain(_ tagName: String) {
        let queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName as AnyObject
        ]
        SecItemDelete(queryFilter as CFDictionary)
    }
    
    // Get a SecKeyRef from keychain
    fileprivate static func getRSAKeyFromKeychain(_ tagName: String) -> SecKey? {
        let queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName as AnyObject,
            //String(kSecAttrAccessible)    : kSecAttrAccessibleWhenUnlocked,
            String(kSecReturnRef)         : true as AnyObject
        ]
        
        var keyPtr: AnyObject?
        let result = SecItemCopyMatching(queryFilter as CFDictionary, &keyPtr)
        if ( result != noErr || keyPtr == nil ) {
            return nil
        }
        return keyPtr as! SecKey?
    }
}


// MARK: - 其他扩展方法
extension SkySafe {
    
    static func base64_decode(_ string: String) -> Data? {
        return Data(base64Encoded: string, options: [.ignoreUnknownCharacters])
    }
    
    // 格式化
    static func formatBySha1(targetData: Data?) -> NSData? {
        guard let rData = targetData else { return nil }
        let outputLength = Int(CC_SHA1_DIGEST_LENGTH)
        var digest = [UInt8](repeating: 0, count: outputLength)
        CC_SHA1([UInt8](rData), CC_LONG(rData.count), &digest)
        return NSData(bytes: digest, length: outputLength)
//        return Data(bytes: digest, count: outputLength)
    }
}



// MARK: - 公钥读取 私钥读取
extension SkySafe {
    
    // 公钥读取
    fileprivate static func stripPublicKeyHeader(_ pubkey: Data) -> Data? {
        if ( pubkey.count == 0 ) {
            return nil
        }
        
        var keyAsArray = [UInt8](repeating: 0, count: pubkey.count / MemoryLayout<UInt8>.size)
        (pubkey as NSData).getBytes(&keyAsArray, length: pubkey.count)
        
        var idx = 0
        if (keyAsArray[idx] != 0x30) {
            return nil
        }
        idx += 1
        
        if (keyAsArray[idx] > 0x80) {
            idx += Int(keyAsArray[idx]) - 0x80 + 1
        } else {
            idx += 1
        }
        
        let seqiod = [UInt8](arrayLiteral: 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00)
        for i in idx..<idx+15 {
            if ( keyAsArray[i] != seqiod[i-idx] ) {
                return nil
            }
        }
        idx += 15
        
        if (keyAsArray[idx] != 0x03) {
            return nil
        }
        idx += 1
        
        if (keyAsArray[idx] > 0x80) {
            idx += Int(keyAsArray[idx]) - 0x80 + 1;
        } else {
            idx += 1
        }
        
        if (keyAsArray[idx] != 0x00) {
            return nil
        }
        idx += 1
        //return pubkey.subdata(in: idx..<keyAsArray.count - idx)
        //return pubkey.subdata(in: NSMakeRange(idx, keyAsArray.count - idx))
        return pubkey.subdata(in:Range(NSMakeRange(idx, keyAsArray.count - idx))!)
    }
    
    // 私钥读取
    fileprivate static func stripPrivateKeyHeader(_ privkey: Data) -> Data? {
        if ( privkey.count == 0 ) {
            return nil
        }
        
        var keyAsArray = [UInt8](repeating: 0, count: privkey.count / MemoryLayout<UInt8>.size)
        (privkey as NSData).getBytes(&keyAsArray, length: privkey.count)
        
        //magic byte at offset 22, check if it's actually ASN.1
        var idx = 22
        if ( keyAsArray[idx] != 0x04 ) {
            return nil
        }
        idx += 1
        
        //now we need to find out how long the key is, so we can extract the correct hunk
        //of bytes from the buffer.
        var len = Int(keyAsArray[idx])
        idx += 1
        let det = len & 0x80 //check if the high bit set
        if (det == 0) {
            //no? then the length of the key is a number that fits in one byte, (< 128)
            len = len & 0x7f
        } else {
            //otherwise, the length of the key is a number that doesn't fit in one byte (> 127)
            var byteCount = Int(len & 0x7f)
            if (byteCount + idx > privkey.count) {
                return nil
            }
            //so we need to snip off byteCount bytes from the front, and reverse their order
            var accum: UInt = 0
            var idx2 = idx
            idx += byteCount
            while (byteCount > 0) {
                //after each byte, we shove it over, accumulating the value into accum
                accum = (accum << 8) + UInt(keyAsArray[idx2])
                idx2 += 1
                byteCount -= 1
            }
            // now we have read all the bytes of the key length, and converted them to a number,
            // which is the number of bytes in the actual key.  we use this below to extract the
            // key bytes and operate on them
            len = Int(accum)
        }
        
        //return privkey.subdata(in: idx..<len)
        //return privkey.subdata(in: NSMakeRange(idx, len))
        return privkey.subdata(in: Range(NSMakeRange(idx, len))!)
    }
    
}


extension String {
    // 格式化
    public func sky_sha256() -> String {
        guard let rData = self.data(using: String.Encoding.utf8) else { return "" }
        let outputLength = Int(CC_SHA256_DIGEST_LENGTH)
        var digest = [UInt8](repeating: 0, count: outputLength)
        CC_SHA256([UInt8](rData), CC_LONG(rData.count), &digest)
        let rspData = Data(bytes: digest, count: outputLength)
        return String(data: rspData, encoding: String.Encoding.utf8) ?? ""
    }
}
