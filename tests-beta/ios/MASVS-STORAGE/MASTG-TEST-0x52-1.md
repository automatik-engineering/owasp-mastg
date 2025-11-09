---
platform: ios
title: References to APIs for Storing Unencrypted Data in Private Storage
id: MASTG-TEST-0x52-1
type: [static]
profiles: [L2]
best-practices: [MASTG-BEST-00xx]
weakness: MASWE-0006
---

## Overview

This test checks whether the app obtains a path to Private Storage (the app sandbox) and identifies code locations that could write unencrypted sensitive data there. It focuses on:

- APIs commonly used to persist data in the app sandbox, including the Documents, Library, Caches, and Application Support directories, as well as `UserDefaults`. See @MASTG-KNOW-0091 for details.
- Keychain APIs used to store sensitive data securely within the Keychain or by using a key from the Keychain to encrypt data before writing to Private Storage. See @MASTG-KNOW-0057 for details.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 and look for uses of file system APIs that create or write files.
2. Run a static analysis tool such as @MASTG-TOOL-0073 and look for uses of Keychain APIs and include the specific flags used.

## Observation

The output should contain:

- A list of locations where the app writes or may write data to Private Storage.
- A list of locations where the app uses Keychain APIs, including access control and accessibility attributes.

## Evaluation

The test case fails if there's no indication that sensitive data is protected when written to Private Storage. For example, if you cannot find any code paths performing encryption before writes, or the Keychain API isn't used to store sensitive data securely or to derive encryption keys for data written to Private Storage.
