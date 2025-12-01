---
platform: android
title: Uses of Hardcoded Security Providers
id: MASTG-DEMO-0071
code: [java]
test: MASTG-TEST-0307
---

### Sample

The code snippet below shows sample code that demonstrates both insecure and secure usage of security providers in `getInstance` calls.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-hardcoded-security-provider.yaml }}

{{ run.sh }}

### Observation

The rule has identified instances in the code file where a security provider is explicitly specified. The specified line numbers can be located in the reverse-engineered code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances:

- Line 31 uses the deprecated "BC" (BouncyCastle) provider with `Cipher.getInstance`. This is deprecated since Android 9 and removed in Android 12.
- Line 33 uses the "SunJCE" provider which is not available on Android and will cause a runtime exception.
- Line 35 uses a custom third-party provider "CustomProvider" which may not be regularly updated or patched.

The following cases are correctly handled and do not trigger the rule:

- Line 28 uses `Cipher.getInstance("AES/GCM/NoPadding")` without specifying a provider, which uses the default AndroidOpenSSL (Conscrypt) provider.
- Line 38 uses `KeyStore.getInstance("AndroidKeyStore")` which is the correct way to access the Android Keystore system.

