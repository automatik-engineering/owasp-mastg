---
title: Hardcoded Security Provider
platform: android
id: MASTG-TEST-0307
type: [static]
weakness: MASWE-0020
best-practices: [MASTG-BEST-0020]
profiles: [L1, L2]
---

## Overview

Android cryptography APIs based on the Java Cryptography Architecture (JCA) allow developers to specify a [security provider](https://developer.android.com/reference/java/security/Provider.html) when calling `getInstance` methods. However, explicitly specifying a provider is generally discouraged on modern Android versions because it can lead to security issues and compatibility problems.

Apps that target Android 9 (API level 28) or above [will get an error if they specify a security provider](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html). The `Crypto` provider was deprecated in Android 7.0 (API level 24) and [removed in Android 9](https://developer.android.com/about/versions/pie/android-9.0-changes-all#conscrypt_implementations_of_parameters_and_algorithms). The BouncyCastle provider was [deprecated in Android 9 and removed in Android 12](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle).

The default provider on Android is `AndroidOpenSSL` (Conscrypt), which is regularly updated and patched. For more information, see @MASTG-KNOW-0011.

**Exceptions:**

- `KeyStore.getInstance("AndroidKeyStore")` is allowed because it specifically requests the Android Keystore system.
- If a security provider is required for compatibility with older Android versions, consider bundling [Conscrypt](https://github.com/google/conscrypt) explicitly.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary to look for calls to `getInstance` that explicitly specify a security provider.

## Observation

The output should contain a list of locations where a security provider is explicitly specified in `getInstance` calls.

## Evaluation

The test case fails if you find `getInstance` calls that explicitly specify a security provider other than `AndroidKeyStore` for `KeyStore` operations. Review each instance to determine if the hardcoded provider is necessary and if it may introduce security vulnerabilities or compatibility issues.
