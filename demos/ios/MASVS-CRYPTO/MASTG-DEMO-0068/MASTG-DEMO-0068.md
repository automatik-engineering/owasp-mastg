---
platform: ios
title: Uses of Broken Encryption Modes in CommonCrypto with r2
code: [swift]
id: MASTG-DEMO-0068
test: MASTG-TEST-0304
---

### Sample

The snippet below shows sample code that uses the insecure ECB (Electronic Codebook) mode when encrypting data with CommonCrypto's `CCCrypt` function. ECB mode is vulnerable because it encrypts identical plaintext blocks to identical ciphertext blocks, revealing patterns in the data.

{{ MastgTest.swift # function.asm # decompiled-o1-review.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ ccecb.r2 }}

{{ run.sh }}

### Observation

The output contains the disassembled code of the function using `CCCrypt` with ECB mode.

{{ output.txt }}

### Evaluation

Inspect the disassembled code to identify the use of insecure encryption modes.

In [CommonCryptor.h](https://web.archive.org/web/20240606000307/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h) you can find the definition of the `CCCrypt` function:

```c
CCCryptorStatus CCCrypt(
    CCOperation op,         /* kCCEncrypt, etc. */
    CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
    CCOptions options,      /* kCCOptionPKCS7Padding, kCCOptionECBMode, etc. */
    const void *key,
    size_t keyLength,
    const void *iv,         /* optional initialization vector */
    const void *dataIn,     /* optional per op and alg */
    size_t dataInLength,
    void *dataOut,          /* data RETURNED here */
    size_t dataOutAvailable,
    size_t *dataOutMoved);
```

There you will also find the `options` parameter which can include `kCCOptionECBMode`:

```c
/*!
    @enum        CCOptions
    @abstract    Options flags, passed to CCCryptorCreate().

    @constant    kCCOptionPKCS7Padding   Perform PKCS7 padding.
    @constant    kCCOptionECBMode        Electronic Code Book Mode.
                                         Default is CBC.
*/
enum {
    kCCOptionPKCS7Padding   = 0x0001,
    kCCOptionECBMode        = 0x0002,
};
typedef uint32_t CCOptions;
```

With this information we can now inspect the disassembled code and we'll see that the ECB mode option (`kCCOptionECBMode`) can be found by its numeric value `2` or `0x0002` in the third argument of the `CCCrypt` function (`w2`). The `CCCrypt` function is called with the ECB mode option, AES algorithm, and a key of 16 bytes:

{{ evaluation.txt }}

The test fails because ECB mode was found in the code.

**Note**: Using artificial intelligence we're able to decompile the disassembled code and review it. The output is a human-readable version of the assembly code. The AI decompiled code may not be perfect and might contain errors but, in this case, it clearly shows the use of `CCCrypt` with the `kCCOptionECBMode` option.
