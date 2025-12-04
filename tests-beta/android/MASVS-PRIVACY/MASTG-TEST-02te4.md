---
platform: android
title: Identifying Sensitive Data Sent via Network Calls
id: MASTG-TEST-02te4
type: [dynamic]
weakness: MASWE-0108
prerequisites:
  - identify-sensitive-data
profiles: [P]
---

## Overview

This test verifies whether an app is sending sensitive data (e.g., PII) via network calls.

## Steps

1. Use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001 to hook network functions and try to detect PII or in their calls.
2. Use the backtraces to find out which component is sending what PII or secrets. This should also include the corresponding network domains.

## Observation

The output should contain a list of the locations where network functions are called and the data being sent.

## Evaluation

The test case fails if you can find sensitive data being passed to these network functions in the app code, indicating that the app is sharing sensitive data via network calls. If no such data sharing is found, the test case passes.
