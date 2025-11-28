---
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

The rule correctly identified one instance in the compiled Java code where an asymmetric key is configured for both encryption/decryption and signing/verification (a purpose value of 15), violating key separation.

{{ output.txt }}

### Evaluation

The test fails because the key is used for multiple purposes.

On Line 83 the key is generated with the integer purpose `15`, which is the bitwise OR of `PURPOSE_ENCRYPT` (`1`), `PURPOSE_DECRYPT` (`2`), `PURPOSE_SIGN` (`4`), and `PURPOSE_VERIFY` (`8`). This insecure practice allows the same private key to be used for multiple distinct cryptographic operations. If the key is compromised during one operation (e.g., encryption), the integrity of signatures made with the same key is also compromised.
