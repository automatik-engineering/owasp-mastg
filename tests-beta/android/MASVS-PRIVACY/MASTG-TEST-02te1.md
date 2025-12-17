---
platform: android
title: References to SDK APIs Known to Handle Sensitive Data
id: MASTG-TEST-02te1
type: [static]
weakness: MASWE-0112
profiles: [P]
---

## Overview

This test verifies whether an app references SDK (third-party library) APIs known to handle sensitive data.

As a prerequisite, we need to identify the SDK APIs (methods) it uses as entry points for data collection by reviewing the library's documentation or codebase. For example, [FirebaseAnalytics](https://firebase.google.com/docs/analytics)'s class `com.google.firebase.analytics.FirebaseAnalytics` has the method `logEvent` used to log data. The method to look for would be `logEvent` in class `com.google.firebase.analytics.FirebaseAnalytics`.

> Note: This test detects only **potential** sensitive data handling. For **confirming** that actual user data are being shared, please refer to @MASTG-TEST-02te3.

## Steps

1. Use @MASTG-TECH-0013 to reverse engineer the app.
2. Use @MASTG-TECH-0014 to look for uses of these methods where sensitive data may be passed to the SDK.

## Observation

The output should list the locations where SDK methods are called.

## Evaluation

The test case fails if you can find the use of these SDK methods in the app code, indicating that the app is sharing data with the third-party SDK. If no such references are found, the test case passes.
