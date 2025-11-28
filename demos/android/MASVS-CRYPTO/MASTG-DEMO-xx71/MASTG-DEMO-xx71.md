---
platform: android
title: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes With Frida
id: MASTG-DEMO-xx71
code: [kotlin]
test: MASTG-TEST-0xx2
---

### Sample

In this sample, we reuse code from @MASTG-DEMO-xx70 and intercept the cryptographic operations at runtime (including encryption, decryption, signing, and verification) to demonstrate the misuse of an asymmetric key pair for multiple purposes.

{{ ../MASTG-DEMO-xx70/MastgTest.kt }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C` and/or `q` to quit the Frida CLI

{{ script.js # run.sh }}

### Observation

The output shows all usages of cryptographic operations.

{{ output.txt }}

Note all `WARNING` messages in the output.

### Evaluation

The test failed because the same key was detected being reused for different cryptographic actions:

- Signing (Line 35 in output.txt)
- Verifying (Line 51 in output.txt)

The warning in output.txt points to the key identified as `sign/verify with key: "android.security.keystore2.AndroidKeyStoreRSAPrivateKey@3818961"`. By searching output.txt for all occurrences of the object reference `@3818961`, we can trace the key's usage back to the first time it was used.

```default
🔒 *** Cipher.init(Key) HOOKED ***
  encryption/decryption with key: "android.security.keystore2.AndroidKeyStoreRSAPrivateKey@3818961"
  Stack Trace:
    javax.crypto.Cipher.init(Native Method)
    org.owasp.mastestapp.MastgTest.decrypt(MastgTest.kt:145)
```

Therefore, it is clear this key pair was used for Signing/Verifying after being previously used for Encrypting/Decrypting.
