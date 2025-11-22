import SwiftUI
import CommonCrypto

// SUMMARY: This sample demonstrates the use of insecure ECB encryption mode in CommonCrypto.

struct MastgTest {
    static func mastgTest(completion: @escaping (String) -> Void) {
        let key = "0123456789abcdef" // 16-byte key for AES-128
        let data = "This is a sample text for ECB mode testing!".data(using: .utf8)!
        
        // Create a buffer for encrypted data
        var encryptedBytes = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var numBytesEncrypted: size_t = 0
        
        // FAIL: [MASTG-TEST-0304] Using ECB mode (kCCOptionECBMode) which is insecure
        let cryptStatus = data.withUnsafeBytes { dataBytes in
            key.withCString { keyBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),              // Encrypt
                    CCAlgorithm(kCCAlgorithmAES),         // AES Algorithm
                    CCOptions(kCCOptionECBMode),          // ECB Mode (INSECURE!)
                    keyBytes, kCCKeySizeAES128,           // Key and key length
                    nil,                                  // No IV needed for ECB
                    dataBytes.baseAddress, data.count,    // Input data
                    &encryptedBytes, encryptedBytes.count, // Output data
                    &numBytesEncrypted                    // Number of bytes encrypted
                )
            }
        }
        
        if cryptStatus == kCCSuccess {
            let encryptedData = Data(bytes: encryptedBytes, count: numBytesEncrypted)
            let encryptedHex = encryptedData.map { String(format: "%02hhx", $0) }.joined()
            let value = "Original:\n\n \(String(data: data, encoding: .utf8)!)\n\nEncrypted with ECB mode (Hex):\n \(encryptedHex)"
            completion(value)
        } else {
            completion("Encryption failed with status: \(cryptStatus)")
        }
    }
}
