---
platform: android
title: References to asymmetric key pair used for multiple purposes
id: MASTG-TEST-0x15-1
type: [static]
weakness: MASWE-0012
profiles: [L1, L2, P]
---

## Overview

This test verifies that asymmetric keys are used for only one clearly defined purpose, as required by NIST. This prevents a single key pair from being reused across different cryptographic functions, which can weaken security boundaries. If one key is used for more than one purpose, an attacker could misuse one part of the system to trick or break another, potentially causing fake or tampered data to be accepted.

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

The output should contain a list of locations where asymmetric keys are created, along with backtraces showing each KeyPair instantiation

## Evaluation

The test case fails if you find any keys with mixed roles as described in **Steps** section.

## References

- [NIST.SP.800 - Recommendation for Key Management (part 1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
