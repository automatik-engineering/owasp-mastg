---
platform: ios
title: Runtime Use of the Keychain API to Exclude Data from Backups and Prevent Access on Other Devices
id: MASTG-TEST-0x58
type: [dynamic]
weakness: MASWE-0004
best-practices: [MASTG-BEST-0023]
profiles: [L1, L2, P]
---

## Overview

This test verifies whether your app correctly uses the Keychain API to exclude sensitive data from backups so it won't be transferred to other devices.

An app can restrict data access to the current device using [`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly) or [`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly). However, if a device is backed up and later restored on the same device, the data will also be restored. Therefore, these flags only prevent the data from being transferred to other devices.

## Steps

1. Use runtime method hooking (see @MASTG-TECH-0095) to look for uses of [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) and the specific flags.
2. Exercise the app to trigger the creation of entries in the Keychain.

## Observation

The output should contain a list of locations where the `SecAccessControlCreateWithFlags` function is called, including all used flags.

## Evaluation

The test case fails if Keychain items do not satisfy your app's security requirements. For example, if your app stores sensitive data that should be accessible only on the current device, the corresponding Keychain item should use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` or `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
