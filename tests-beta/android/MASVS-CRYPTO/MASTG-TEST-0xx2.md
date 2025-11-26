---
platform: android
title: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes
id: MASTG-TEST-0xx2
type: [dynamic]
weakness: MASWE-0012
profiles: [L1, L2, P]
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0xx1, but it focuses on intercepting cryptographic operations rather than generating keys with multiple properties.

## Steps

1. Run a dynamic analysis tool such as @MASTG-TOOL-0001.
2. Intercept all functions that use an asymmetric key to cryptographic operation. For example:

   - [`Cipher.init(int opmode, Key key, AlgorithmParameters params)`](https://developer.android.com/reference/javax/crypto/Cipher#init(int,%20java.security.Key,%20java.security.AlgorithmParameters))
   - [`Signature.initSign(PrivateKey privateKey)`](https://developer.android.com/reference/java/security/Signature#initSign(java.security.PrivateKey))
   - [`Signatur.initVerify(PublicKey publicKey)`](https://developer.android.com/reference/java/security/Signature#initVerify(java.security.PublicKey))

3. Ensure that each key one key-pair is not used for multiple purposes

## Observation

The output should contain a list of all cryptographic operations together with their corresponding keys. Next to each entry, it should be indicated whether or not the key has been used previously for a different purpose.

## Evaluation

The test case fails if you find any keys used for multiple purpose.
