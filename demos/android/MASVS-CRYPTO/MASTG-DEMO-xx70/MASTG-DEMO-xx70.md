platform: android
title: References to Asymmetric Key Pairs Used For Multiple Purposes With Semgrep
id: MASTG-DEMO-xx70
code: [java]
test: MASTG-TEST-0xx1
---

### Sample

This sample generates an RSA key pair using `KeyGenParameterSpec` with multiple purposes: `PURPOSE_SIGN`, `PURPOSE_VERIFY`, `PURPOSE_ENCRYPT`, and `PURPOSE_DECRYPT`. It subsequently uses it for encryption, decryption, signing, and verification.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Run the @MASTG-TOOL-0110 rule, as defined below, against the sample code.

{{ ../../../../rules/mastg-android-asymmetric-key-pair-used-for-multiple-purposes.yml }}

{{ run.sh }}

### Observation

The rule flags the constructor call to `KeyGenParameterSpec.Builder` in the decompiled Java. This is an observation-only finding meant to capture all key generation instances. You must evaluate the configured purposes to determine whether multiple distinct categories (cipher, signature, wrapping) are combined.

{{ output.txt }}

### Evaluation

The test fails because, after reviewing the observation, the key is indeed configured for multiple purposes.

In this sample, the constructor receives a combined purpose value of `15`, which is the bitwise OR of `PURPOSE_ENCRYPT` (`1`), `PURPOSE_DECRYPT` (`2`), `PURPOSE_SIGN` (`4`), and `PURPOSE_VERIFY` (`8`). This mixes encryption/decryption with signing/verification and violates key separation: keys used for different functions must be distinct. If the key is compromised during one operation (for example, encryption), signatures made with the same key are also impacted.
