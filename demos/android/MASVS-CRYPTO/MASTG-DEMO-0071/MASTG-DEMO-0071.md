---
platform: android
title: References to Asymmetric Key Pairs Used For Multiple Purposes (ripgrep)
id: MASTG-DEMO-0071
code: [java]
test: MASTG-TEST-0307
---

### Sample

This sample generates an RSA key pair using `KeyGenParameterSpec` with multiple purposes: `PURPOSE_SIGN`, `PURPOSE_VERIFY`, `PURPOSE_ENCRYPT`, and `PURPOSE_DECRYPT`. It subsequently uses it for encryption, decryption, signing, and verification.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Run the ripgrep-based script:

{{ run.sh }}

### Observation

We capture constructor calls to `KeyGenParameterSpec.Builder` via ripgrep and store observations in `output.json` containing: `file`, `line`, `class`, `keystoreAlias`, and `purposes`.

{{ output.json }}

### Evaluation

The test fails because, after reviewing the observation, the key is indeed configured for multiple purposes.

We inspect the output to see whether `purposes` mixes categories (cipher: 1|2, signature: 4|8, wrap: 32).

{{ evaluation.txt # evaluate.py }}

In this sample, the constructor receives a combined purpose value of `15`, which is the bitwise OR of `PURPOSE_ENCRYPT` (`1`), `PURPOSE_DECRYPT` (`2`), `PURPOSE_SIGN` (`4`), and `PURPOSE_VERIFY` (`8`). This mixes encryption/decryption with signing/verification and violates key separation: keys used for different functions must be distinct. If the key is compromised during one operation (for example, encryption), signatures made with the same key are also impacted.
