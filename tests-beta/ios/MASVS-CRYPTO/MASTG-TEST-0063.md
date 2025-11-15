---
platform: ios
title: Insecure Random API Usage
id: MASTG-TEST-0063
type: [static]
weakness: MASWE-0027
profiles: [L1, L2]
---

## Overview

iOS apps sometimes use insecure [pseudorandom number generators (PRNGs)](../../../Document/0x06e-Testing-Cryptography.md#random-number-generation) instead of cryptographically secure ones. While Apple provides the cryptographically secure [`SecRandomCopyBytes`](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes) API, developers may inadvertently use less secure alternatives such as:

- `arc4random()` family functions (while better than standard random, they may not meet all cryptographic security requirements in certain contexts)
- Standard C library functions like `rand()` and `random()`, which are linear congruential generators
- Custom implementations without cryptographic guarantees

The `SecRandomCopyBytes` API is the recommended approach for generating cryptographically secure random numbers in iOS. In Swift, it is defined as:

```swift
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

The [Objective-C version](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc) is:

```objectivec
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

Usage example:

```objectivec
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

If random numbers are used in security-relevant contexts (e.g., generating encryption keys, tokens, nonces, or initialization vectors), only cryptographically secure PRNGs should be used. Refer to the ["random number generation" guide](../../../Document/0x06e-Testing-Cryptography.md#random-number-generation) for further details.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary and look for insecure random APIs such as `rand`, `random`, `srand`, `srandom`, or non-secure custom implementations.
2. For each of the identified API uses, verify the context by decompiling or disassembling the code to determine if the random values are used in security-relevant operations.

## Observation

The output should contain a list of locations where insecure random APIs are used.

## Evaluation

The test case fails if random numbers generated using insecure APIs are used in security-relevant contexts, such as:

- Generating cryptographic keys, initialization vectors (IVs), or nonces
- Creating authentication tokens or session identifiers
- Generating passwords or PINs
- Any other security-critical operations requiring unpredictability

Ensure that any identified uses are indeed security-relevant. Avoid false positives by verifying the context - for example, random numbers used for non-security purposes like UI animations or game mechanics may not require cryptographic security.
