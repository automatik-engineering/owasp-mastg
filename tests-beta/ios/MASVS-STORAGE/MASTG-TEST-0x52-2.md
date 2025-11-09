---
platform: ios
title: Runtime Monitoring of Storage and Keychain Usage in the App Sandbox
id: MASTG-TEST-0x52-2
type: [dynamic]
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
profiles: [L2]
weakness: MASWE-0006
best-practices: [MASTG-BEST-00xx]
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0x52-1 and is designed to be used together with @MASTG-TEST-0x52-3.

It uses runtime method hooking to monitor File System and Keychain API usage in order to:

1. Identify where sensitive data is written to Private Storage (the app sandbox).
2. Capture Keychain operations.
3. Correlate whether sensitive data is protected (stored only in the Keychain or encrypted prior to file persistence).

## Steps

1. Use runtime method hooking (see @MASTG-TECH-0095) and look for uses of file system APIs that create or write files.
2. Use runtime method hooking (see @MASTG-TECH-0095) and look for uses of Keychain APIs.
3. Exercise application features that could handle sensitive data (authentication flows, session establishment, offline caching, profile viewing/editing, cryptographic operations, secure messaging, payment, or token refresh logic).

## Observation

The output should contain:
- A list of observed Keychain API invocations with: function, call stack (symbolicated if possible) and optionally additional query dictionary attributes (sanitized), accessibility class and access control flags.
- A list of observed file write / create operations with: function, call stack (symbolicated if possible), target path, file type/extension, approximate size, hash (e.g., SHA-256), and whether captured contents appear to include sensitive data (credentials, tokens, keys, PII, session identifiers).

## Evaluation

The test case fails if there's no indication that sensitive data is protected when written to Private Storage. For example, if you cannot find any code paths performing encryption before writes, or the Keychain API isn't used to store sensitive data securely or to derive encryption keys for data written to Private Storage.

Determining whether data is encrypted when written to Private Storage may be challenging. However, by monitoring the APIs used for writing data and analyzing the data written, you can infer whether encryption is being applied based on the methods and libraries used. You'll have to correlate the data written to Private Storage with the APIs used to write it, as identified through runtime method hooking. You'll also have to correlate the File System APIs with the Keychain APIs to verify that they are used together to store sensitive data securely. Sensitive data can be stored securely in the Keychain or be encrypted using a key from the Keychain before being written to Private Storage.
