---
platform: android
title: Determine Sensitive Data Sent to embedded SDKs
id: MASTG-TEST-02te3
type: [dynamic]
weakness: MASWE-0112
prerequisites:
  - identify-sensitive-data
profiles: [P]
---

## Overview

This test verifies whether an app is sending sensitive data to an embedded SDK (third-party library) via its APIs (methods).

> Note: For identifying whether an app references an SDK known to handle sensitive data, please refer to @MASTG-TEST-02te1. This test focuses on confirming actual data sharing.

## Steps

1. Use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001 to hook SDK methods known to handle sensitive data and try to detect sensitive data in their calls.

## Observation

The output should contain a list of the locations where SDK methods are called.

## Evaluation

The test case fails if you can find sensitive data being passed to these SDK methods in the app code, indicating that the app is sharing sensitive data with the third-party SDK. If no such data sharing is found, the test case passes.
