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

    // Insecure: libc rand seeded with time
    static func generateInsecureRandomTokenRand() -> String {
        var token = ""

        for _ in 0..<16 {
            let value = c_rand() % 256
            token += String(format: "%02x", value)
        }
        return token
    }

    // Insecure: custom LCG seeded with time
    static func generateInsecureRandomTokenLCG() -> String {
        var token = ""
        for _ in 0..<16 {
            let b = lcgRandByte()
            token += String(format: "%02x", b)
        }
        return token
    }

    // Discouraged: Swift random APIs used for crypto tokens
    // These APIs are not intended as a token generation interface
    //    2717 ms  $ss17FixedWidthIntegerPsE6random2inxSNyxG_tFZ()
    //    2717 ms     | swift_stdlib_random()
    //    2717 ms     |    | arc4random_buf(buf=0x16ef65c78, nbytes=0x8)
    static func generateInsecureRandomTokenSwiftRandom() -> String {
        var token = ""
        for _ in 0..<16 {
            let b = UInt8.random(in: 0...255)
            token += String(format: "%02x", b)
        }
        return token
    }
    
    // Discouraged: direct read from /dev/random
    // This works and it's cryptographycally secure but is not the recommended interface on Apple platforms
    static func generateInsecureRandomTokenDevRandom() -> String {
        let count = 16

        let fd = open("/dev/random", O_RDONLY)
        if fd < 0 {
            return "Error opening dev random"
        }

        var buffer = [UInt8](repeating: 0, count: count)
        let readCount = read(fd, &buffer, count)
        close(fd)

        if readCount != count {
            return "Error reading dev random"
        }

        return buffer.map { String(format: "%02x", $0) }.joined()
    }
    
    // Discouraged: arc4random_uniform used as a crypto token source
    // On Apple platforms arc4random_uniform is strong, but it is not the recommended crypto API
    static func generateInsecureRandomTokenArc4RandomUniform() -> String {
        var token = ""
        for _ in 0..<16 {
            let value = arc4random_uniform(256)
            token += String(format: "%02x", value)
        }
        return token
    }

    // Discouraged: arc4random used as a crypto token source
    // On Apple platforms arc4random is strong, but it is not the recommended crypto API
    static func generateInsecureRandomTokenArc4Random() -> String {
        var token = ""
        for _ in 0..<16 {
            let value = arc4random() % 256
            token += String(format: "%02x", value)
        }
        return token
    }
    
    // Discouraged: SystemRandomNumberGenerator used as a token source
    // This generator is suitable for nondeterministic randomness but is not a crypto token API
    static func generateInsecureRandomTokenSystemRNG() -> String {
        var token = ""
        var rng = SystemRandomNumberGenerator()

        for _ in 0..<16 {
            let b = UInt8.random(in: 0...255, using: &rng)
            token += String(format: "%02x", b)
        }
        return token
    }
    
    // Discouraged: drand48 used as a token source
    // This generator is suitable for nondeterministic randomness but is not a crypto token API
    static func generateInsecureRandomTokenDrand48() -> String {
        var token = ""
        for _ in 0..<16 {
            let value = Int(drand48() * 256.0) % 256
            token += String(format: "%02x", value)
        }
        return token
    }
    
    // Discouraged: CCRandomGenerateBytes used as a token source
    static func generateSecureRandomTokenCC() -> String {
        var buffer = [UInt8](repeating: 0, count: 16)
        let status = CCRandomGenerateBytes(&buffer, buffer.count)

        if status != kCCSuccess {
            return "Error generating random bytes with CCRandomGenerateBytes"
        }

        return buffer.map { String(format: "%02x", $0) }.joined()
    }

    // Secure: SecRandomCopyBytes
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
        
        // srand48(time(nil))

        let value = """
        Insecure Random Token using libc rand seeded with time
        Token: \(generateInsecureRandomTokenRand())

        Insecure Random Token using custom LCG seeded with time
        Token: \(generateInsecureRandomTokenLCG())

        Discouraged Random Token using Swift random API as token source
        Token: \(generateInsecureRandomTokenSwiftRandom())
        
        Discouraged Random Token using dev random
        Token: \(generateInsecureRandomTokenDevRandom())

        Discouraged Random Token using arc4random_uniform misused for crypto tokens
        Token: \(generateInsecureRandomTokenArc4RandomUniform())
        
        Discouraged Random Token using arc4random misused for crypto tokens
        Token: \(generateInsecureRandomTokenArc4Random())

        Discouraged Random Token using SystemRandomNumberGenerator
        Token: \(generateInsecureRandomTokenSystemRNG())
        
        Discouraged Random Token using drand48
        Token: \(generateInsecureRandomTokenDrand48())

        Secure Random Token using CCRandomGenerateBytes
        Token: \(generateSecureRandomTokenCC())

        Secure Random Token using SecRandomCopyBytes
        Token: \(generateSecureRandomToken())
        """

        completion(value)
    }
}
