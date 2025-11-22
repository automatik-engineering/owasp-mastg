// AI-decompiled version of the assembly code
// This is a human-readable representation and may contain inaccuracies

import CommonCrypto

func encryptWithECB(data: UnsafePointer<UInt8>, 
                    dataLength: Int, 
                    key: UnsafePointer<UInt8>,
                    keyLength: Int,
                    outputBuffer: UnsafeMutablePointer<UInt8>,
                    outputLength: Int,
                    bytesWritten: UnsafeMutablePointer<Int>) -> CCCryptorStatus {
    
    // Call CCCrypt with ECB mode (INSECURE!)
    let status = CCCrypt(
        CCOperation(kCCEncrypt),           // w0 = 0: Encrypt operation
        CCAlgorithm(kCCAlgorithmAES),      // w1 = 0: AES algorithm
        CCOptions(kCCOptionECBMode),       // w2 = 2: ECB mode (INSECURE!)
        key,                               // x3: Key pointer
        keyLength,                         // w4 = 0x10: 16 bytes key length
        nil,                               // x5 = 0: No IV (ECB doesn't use IV)
        data,                              // x6: Input data pointer
        dataLength,                        // x7: Input data length
        outputBuffer,                      // [stack]: Output buffer
        outputLength,                      // [stack]: Output buffer size
        bytesWritten                       // [stack]: Bytes written
    )
    
    return status
}

// The use of kCCOptionECBMode (value 2) indicates ECB mode is being used,
// which is insecure for encrypting sensitive data as it reveals patterns.
