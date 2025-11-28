---
platform: android
title: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes
id: MASTG-TEST-0xx2
type: [dynamic]
weakness: MASWE-0012
profiles: [L2]
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0xx1, but it focuses on intercepting cryptographic operations rather than generating keys with multiple purposes.

Some of the relevant functions to intercept are:

- [`Cipher.init(int opmode, Key key, AlgorithmParameters params)`](https://developer.android.com/reference/javax/crypto/Cipher#init(int,%20java.security.Key,%20java.security.AlgorithmParameters)) where `opmode` is one of:
    - `Cipher.ENCRYPT_MODE`
    - `Cipher.DECRYPT_MODE`
    - `Cipher.WRAP_MODE`
    - `Cipher.UNWRAP_MODE`
- [`Signature.initSign(PrivateKey privateKey)`](https://developer.android.com/reference/java/security/Signature#initSign(java.security.PrivateKey))
- [`Signature.initVerify(PublicKey publicKey)`](https://developer.android.com/reference/java/security/Signature#initVerify(java.security.PublicKey))

## Steps

1. Execute a method trace (@MASTG-TECH-0033) (using e.g. @MASTG-TOOL-0001) by attaching to the running app, targeting all functions that use an asymmetric key to perform cryptographic operations.

## Observation

The output should contain a list of all cryptographic operations together with their corresponding keys.

## Evaluation

The test case fails if you find any keys used for multiple roles.

Using the output, ensure that each key (or key pair) is restricted to exactly **one** of the following operations:

- Encryption/Decryption (used in `Cipher` operations with `ENCRYPT_MODE` or `DECRYPT_MODE`)
- Signing/Verification (used in `Signature` operations)
- Key Wrapping (used in `Cipher` operations with `WRAP_MODE` or `UNWRAP_MODE`)
