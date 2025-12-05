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

> Note: This tests detects only **potential** sensitive data handling. For **confirming** that actual user data are being shared, please refer to @MASTG-TEST-02te3.

## Steps

1. Identify common SDK APIs (methods) the SDK uses as entry points to collect data by researching the library's documentation online or its codebase. For example, if the library is `com.example.analytics` and it has a method `trackEvent(String eventName, Map<String, String> properties)` used to accept data, then the method to search for would be `com.example.analytics.trackEvent`.
2. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app code to look for uses of these methods where sensitive data may be passed to the SDK.

## Observation

The output should contain a list of locations where SDK methods are called.

## Evaluation

The test case fails if you can find the use of these SDK methods in the app code, indicating that the app is sharing data with the third-party SDK. If no such references are found, the test case passes.
