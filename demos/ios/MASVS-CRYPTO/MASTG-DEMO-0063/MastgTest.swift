import Foundation
import Security

struct MastgTest {
    // INSECURE: Using standard C library rand() function
    static func generateInsecureRandomToken() -> String {
        var token = ""
        for _ in 0..<16 {
            let randomValue = rand() % 256
            token += String(format: "%02x", randomValue)
        }
        return token
    }
    
    // SECURE: Using SecRandomCopyBytes for cryptographically secure random numbers
    static func generateSecureRandomToken() -> String {
        var randomBytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        
        guard status == errSecSuccess else {
            return "Error generating secure random bytes"
        }
        
        return randomBytes.map { String(format: "%02x", $0) }.joined()
    }
    
    static func mastgTest(completion: @escaping (String) -> Void) {
        // Seed the insecure random number generator
        srand(UInt32(time(nil)))
        
        // Generate multiple tokens to show the insecurity
        let insecureToken1 = generateInsecureRandomToken()
        let insecureToken2 = generateInsecureRandomToken()
        let insecureToken3 = generateInsecureRandomToken()
        
        // Generate secure tokens for comparison
        let secureToken1 = generateSecureRandomToken()
        let secureToken2 = generateSecureRandomToken()
        let secureToken3 = generateSecureRandomToken()
        
        let value = """
        Insecure Random Tokens (using rand()):
        Token 1: \(insecureToken1)
        Token 2: \(insecureToken2)
        Token 3: \(insecureToken3)
        
        Secure Random Tokens (using SecRandomCopyBytes):
        Token 1: \(secureToken1)
        Token 2: \(secureToken2)
        Token 3: \(secureToken3)
        
        Note: The insecure tokens may show patterns or predictability,
        especially if the seed is known or the program is run multiple times
        with the same initial conditions.
        """
        
        completion(value)
    }
}
