---
title: Use Secure Random Number Generator APIs
alias: ios-use-secure-random
id: MASTG-BEST-00x1
platform: ios
---

Use a cryptographically secure pseudorandom number generator provided by the platform or language you are using.

## Swift

Use the [`SecRandomCopyBytes`](https://developer.apple.com/documentation/security/secrandomcopybytes(_:_:_:)) API from the Security framework, which produces cryptographically secure random bytes backed by the system CSPRNG.

For key generation and other cryptographic operations, prefer dedicated cryptographic APIs such as [`CryptoKit`](https://developer.apple.com/videos/play/wwdc2019/709/?time=1295). For example, [`SymmetricKey`](https://developer.apple.com/documentation/cryptokit/symmetrickey) uses [`SystemRandomNumberGenerator`](https://github.com/apple/swift-crypto/blob/4.1.0/Sources/Crypto/Keys/Symmetric/SymmetricKeys.swift#L118) internally, which draws from the system CSPRNG. This avoids manual byte handling and reduces the chance of mistakes.

```swift
// Generating and releasing a cryptographic key for a C Crypto API
let keyByteCount = 256 / 8
var key = Array(repeating: 0 as UInt8, count: keyByteCount)
let err = SecRandomCopyBytes(kSecRandomDefault, keyByteCount, &key)
if err != errSecSuccess {
    // Safely handle the error
}
// Use the key
...
// Zeroize the key
memset_s(&key, keyByteCount, 0, keyByteCount)


// Generating and releasing a cryptographic key with Apple CryptoKit
let key = SymmetricKey(size: .bits256)
// Use the key
...
// When the key goes out of scope, CryptoKit handles cleanup
```

## Other Languages

Consult the standard library or framework to locate the API that exposes the operating system CSPRNG. This is usually the safest path, provided the library itself has no known weaknesses.

For cross-platform or hybrid apps on iOS rely on frameworks that forward calls to the underlying system CSPRNG. For example:

- In Flutter or Dart use [`Random.secure()`](https://api.flutter.dev/flutter/dart-math/Random/Random.secure.html), which is documented as cryptographically secure. It reaches `SecRandomCopyBytes` through [the platform integration layers](https://github.com/dart-lang/sdk/blob/47e77939fce74ffda0b7252f33ba1ced2ea09c52/runtime/bin/crypto_macos.cc#L16). See [this article](https://www.zellic.io/blog/proton-dart-flutter-csprng-prng/) for a security review.
- In React Native use a library such as [`react-native-secure-random`](https://github.com/robhogan/react-native-securerandom) or [`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values), which internally calls `SecRandomCopyBytes` on iOS.
