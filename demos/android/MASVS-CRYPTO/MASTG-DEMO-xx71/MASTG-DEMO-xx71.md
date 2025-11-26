---
platform: android
title: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes With Frida
id: MASTG-DEMO-xx71
code: [kotlin]
test: MASTG-TEST-0xx2
---

### Sample

In this sample, we reuse code from @MASTG-DEMO-xx70 and intercept below cryptographic operations to monitor the key being used:

- [`Cipher.init(int opmode, Key key, AlgorithmParameters params)`](https://developer.android.com/reference/javax/crypto/Cipher#init(int,%20java.security.Key,%20java.security.AlgorithmParameters))
- [`Signature.initSign(PrivateKey privateKey)`](https://developer.android.com/reference/java/security/Signature#initSign(java.security.PrivateKey))
- [`Signature.initVerify(PublicKey publicKey)`](https://developer.android.com/reference/java/security/Signature#initVerify(java.security.PublicKey))

{{ ../MASTG-DEMO-xx70/MastgTest.kt }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C` and/or `q` to quit the Frida CLI

{{ hooks.js # run.sh }}

### Observation

The output shows all usages of cryptographic operations.

{{ output.json }}

### Evaluation

The test fails because one key is reused for the following operations:

- Encryption (Line 23 in output.json)
- Decryption (Line 93 in output.json)
- Signing (Line 159 in output.json)
- Verification (Line 188 in output.json)
