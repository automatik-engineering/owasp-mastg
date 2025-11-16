import Foundation
import Security
import Darwin
import CommonCrypto

// Unsafe bindings to libc srand and rand
@_silgen_name("srand")
func c_srand(_ seed: UInt32)

@_silgen_name("rand")
func c_rand() -> Int32

// Simple linear congruential generator for another insecure example
fileprivate var lcgState: UInt32 = 0

fileprivate func lcgSeed(_ seed: UInt32) {
    lcgState = seed
}

fileprivate func lcgRandByte() -> UInt8 {
    lcgState = 1103515245 &* lcgState &+ 12345
    return UInt8(truncatingIfNeeded: lcgState >> 16)
}

struct MastgTest {

    // Insecure: libc rand seeded with time, predictable and not suitable for cryptography
    static func generateInsecureRandomTokenRand() -> String {
        var token = ""

        for _ in 0..<16 {
            let value = c_rand() % 256
            token += String(format: "%02x", value)
        }
        return token
    }

    // Insecure: custom LCG seeded with time, predictable and not suitable for cryptography
    static func generateInsecureRandomTokenLCG() -> String {
        var token = ""
        for _ in 0..<16 {
            let b = lcgRandByte()
            token += String(format: "%02x", b)
        }
        return token
    }

    // Cryptographically secure on Apple platforms
    // Swift random APIs use SystemRandomNumberGenerator backed by the system CSPRNG via arc4random_buf
    // Shown here as a secure source that is not a dedicated crypto token API
    static func generateInsecureRandomTokenSwiftRandom() -> String {
        var token = ""
        for _ in 0..<16 {
            let b = UInt8.random(in: 0...255)
            token += String(format: "%02x", b)
        }
        return token
    }
    
    // Cryptographically secure: direct read from /dev/random on Apple platforms
    // However, this is a low level interface and is discouraged in favor of SecRandomCopyBytes
    static func generateInsecureRandomTokenDevRandom() -> String {
        let count = 16

        let fd = open("/dev/random", O_RDONLY)
        if fd < 0 {
            return "Error opening /dev/random"
        }

        var buffer = [UInt8](repeating: 0, count: count)
        let readCount = read(fd, &buffer, count)
        close(fd)

        if readCount != count {
            return "Error reading /dev/random"
        }

        return buffer.map { String(format: "%02x", $0) }.joined()
    }
    
    // Cryptographically secure but discouraged as a direct token API
    // On Apple platforms arc4random_uniform is strong, but SecRandomCopyBytes or CryptoKit are preferred
    static func generateInsecureRandomTokenArc4RandomUniform() -> String {
        var token = ""
        for _ in 0..<16 {
            let value = arc4random_uniform(256)
            token += String(format: "%02x", value)
        }
        return token
    }

    // Cryptographically secure but discouraged as a direct token API
    // On Apple platforms arc4random is strong, but it is not the recommended crypto API
    static func generateInsecureRandomTokenArc4Random() -> String {
        var token = ""
        for _ in 0..<16 {
            let value = arc4random() % 256
            token += String(format: "%02x", value)
        }
        return token
    }
    
    // Cryptographically secure: SystemRandomNumberGenerator uses the system CSPRNG
    // It is suitable for cryptographic use, and CryptoKit builds on it
    // Included here to contrast secure generators with insecure ones
    static func generateInsecureRandomTokenSystemRNG() -> String {
        var token = ""
        var rng = SystemRandomNumberGenerator()

        for _ in 0..<16 {
            let b = UInt8.random(in: 0...255, using: &rng)
            token += String(format: "%02x", b)
        }
        return token
    }
    
    // Insecure: drand48 uses a 48 bit linear congruential generator
    // Not thread safe and not suitable for cryptographic purposes
    static func generateInsecureRandomTokenDrand48() -> String {
        var token = ""
        for _ in 0..<16 {
            let value = Int(drand48() * 256.0) % 256
            token += String(format: "%02x", value)
        }
        return token
    }
    
    // Cryptographically secure: CCRandomGenerateBytes uses the system CSPRNG
    // Secure, but a lower level API that is generally discouraged in favor of SecRandomCopyBytes
    static func generateSecureRandomTokenCC() -> String {
        var buffer = [UInt8](repeating: 0, count: 16)
        let status = CCRandomGenerateBytes(&buffer, buffer.count)

        if status != kCCSuccess {
            return "Error generating random bytes with CCRandomGenerateBytes"
        }

        return buffer.map { String(format: "%02x", $0) }.joined()
    }

    // Recommended: SecRandomCopyBytes is the high level, Apple recommended API for secure random bytes
    static func generateSecureRandomToken() -> String {
        var randomBytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)

        guard status == errSecSuccess else {
            return "Error generating secure random bytes"
        }

        return randomBytes.map { String(format: "%02x", $0) }.joined()
    }

    static func mastgTest(completion: @escaping (String) -> Void) {
        // Seed libc rand with current time
        let now = UInt32(time(nil))
        c_srand(now)

        // Seed LCG with the same time to show predictability
        lcgSeed(now)
        
        // Example of seeding drand48 with time, which also makes it predictable if the seed is known
        // srand48(time(nil))

        let value = """
        Insecure random token using libc rand seeded with time
        Token: \(generateInsecureRandomTokenRand())

        Insecure random token using custom LCG seeded with time
        Token: \(generateInsecureRandomTokenLCG())

        Cryptographically secure random token using Swift random API backed by SystemRandomNumberGenerator
        Token: \(generateInsecureRandomTokenSwiftRandom())
        
        Cryptographically secure random token using /dev/random low level interface
        Token: \(generateInsecureRandomTokenDevRandom())

        Discouraged random token using arc4random_uniform as a direct token source
        Token: \(generateInsecureRandomTokenArc4RandomUniform())
        
        Discouraged random token using arc4random as a direct token source
        Token: \(generateInsecureRandomTokenArc4Random())

        Cryptographically secure random token using SystemRandomNumberGenerator directly
        Token: \(generateInsecureRandomTokenSystemRNG())
        
        Insecure random token using drand48 linear congruential generator
        Token: \(generateInsecureRandomTokenDrand48())

        Cryptographically secure random token using CCRandomGenerateBytes lower level API
        Token: \(generateSecureRandomTokenCC())

        Recommended secure random token using SecRandomCopyBytes
        Token: \(generateSecureRandomToken())
        """

        completion(value)
    }
}
