---
title: Broken Symmetric Encryption Modes
platform: ios
id: MASTG-TEST-0304
type: [static, dynamic]
weakness: MASWE-0020
best-practices: [MASTG-BEST-0005]
profiles: [L1, L2]
---

## Overview

To test for the [use of broken encryption modes](../../../Document/0x04g-Testing-Cryptography.md#broken-block-cipher-modes) in iOS apps, we need to focus on methods from cryptographic frameworks and libraries that are used to configure and apply encryption modes.

In iOS development, the `CCCrypt` function from CommonCrypto is the primary API that allows you to specify the encryption mode through the `options` parameter. The [`CCCrypt`](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h) function accepts a `CCOptions` parameter, which controls the mode of operation:

```c
CCCryptorStatus CCCrypt(
    CCOperation op,         /* kCCEncrypt, etc. */
    CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
    CCOptions options,      /* kCCOptionPKCS7Padding, kCCOptionECBMode, etc. */
    const void *key,
    size_t keyLength,
    const void *iv,         /* optional initialization vector */
    const void *dataIn,
    size_t dataInLength,
    void *dataOut,
    size_t dataOutAvailable,
    size_t *dataOutMoved);
```

The `CCOptions` parameter can include `kCCOptionECBMode` (value `0x0002` or `2`) to enable ECB mode. For example:

```swift
CCCrypt(
    CCOperation(kCCEncrypt),
    CCAlgorithm(kCCAlgorithmAES),
    CCOptions(kCCOptionECBMode),  // ECB mode enabled
    ...
)
```

In this test, we're going to focus on symmetric encryption modes such as [ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)).

ECB (defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final)) is generally discouraged [see NIST announcement in 2023](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a) due to its inherent security weaknesses. While not explicitly prohibited, its use is limited and advised against in most scenarios. ECB is a block cipher mode that operates deterministically, dividing plaintext into blocks and encrypting them separately, which reveals patterns in the ciphertext. This makes it vulnerable to attacks like [known-plaintext attacks](https://en.wikipedia.org/wiki/Known-plaintext_attack) and [chosen-plaintext attacks](https://en.wikipedia.org/wiki/Chosen-plaintext_attack).

When `kCCOptionECBMode` is set in the options parameter, the encryption uses ECB mode, which is considered vulnerable. The default behavior (when `kCCOptionECBMode` is not set) is to use CBC mode, which is more secure when used with a proper initialization vector (IV).

You can learn more about ECB and other modes in [NIST SP 800-38A - Recommendation for Block Cipher Modes of Operation: Methods and Techniques](https://csrc.nist.gov/pubs/sp/800/38/a/final). Also check the [Decision to Revise NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation: Methods and Techniques](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a) and [NIST IR 8459 Report on the Block Cipher Modes of Operation in the NIST SP 800-38 Series](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8459.pdf) for the latest information.

**Note**: CryptoKit does not support ECB mode and is therefore not vulnerable to this issue. CryptoKit only supports secure encryption modes like AES-GCM and ChaCha20-Poly1305.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary, or use a dynamic analysis tool like @MASTG-TOOL-0039, and look for uses of `CCCrypt` with the `kCCOptionECBMode` option.

## Observation

The output should contain the disassembled code of the functions using `CCCrypt` with ECB mode enabled.

## Evaluation

The test case fails if you can find the use of `kCCOptionECBMode` (value `2` or `0x0002`) in the third parameter (options) of `CCCrypt` calls within the source code.

**Stay up-to-date**: Make sure to check the latest standards and recommendations from organizations such as the National Institute of Standards and Technology (NIST), the German Federal Office for Information Security (BSI), or any other relevant authority in your region.

**Context Considerations**:

To reduce false positives, make sure you understand the context in which the mode is being used before reporting the associated code as insecure. Ensure that it is being used in a security-relevant context to protect sensitive data.
