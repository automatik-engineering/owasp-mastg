---
platform: android
title: References to Asymmetric Key Pairs Used For Multiple Purposes
id: MASTG-TEST-0xx1
type: [static]
weakness: MASWE-0012
profiles: [L2]
---

## Overview

An asymmetric key has a defined role. A signing key should not decrypt. An encryption key should not sign. A long term key should not serve multiple unrelated protocols. Misuse exposes the key to operations it was never hardened for and creates cross protocol attack paths.

This test verifies that asymmetric keys are used for only one clearly defined purpose, as required by NIST.

Check ["NIST.SP.800-57pt1r5"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) for details.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code.
2. Find uses of `KeyGenParameterSpec.Builder` and its `KeyProperties`.
3. Ensure that each key (or key pair) is restricted to exactly **one** of the following roles:

   - **Signing / verification:** [`KeyProperties.PURPOSE_SIGN`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_SIGN) | [`KeyProperties.PURPOSE_VERIFY`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_VERIFY)
   - **Encryption / decryption:** [`KeyProperties.PURPOSE_ENCRYPT`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_ENCRYPT) | [`KeyProperties.PURPOSE_DECRYPT`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_DECRYPT)
   - **Wrapping / unwrapping keys:** [`KeyProperties.PURPOSE_WRAP_KEY`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_WRAP_KEY)

In other words, ensure that the app doesn't create a key that combines purposes across roles (for example, signing **and** decrypting) which is potentially insecure and must be avoided.

## Observation

The output should contain a list of locations where asymmetric keys are created, along with backtraces showing each `KeyPair` instantiation.

## Evaluation

The test case fails if you find any keys used for multiple purposes.

## References

- [NIST.SP.800 - Recommendation for Key Management (part 1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
