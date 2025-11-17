---
platform: ios
title: Runtime Monitoring of Text Fields Eligible for Keyboard Caching
id: MASTG-TEST-0x55-2
type: [dynamic]
weakness: MASWE-0053
---

## Overview

This test is designed to complement @MASTG-TEST-0x55-1. It monitors all text inputs in the app at runtime and lists every field into which the user has entered text. After each interaction, it reports whether the input is protected against keyboard caching. Therefore, it is important to exercise the app thoroughly.

## Steps

1. Use runtime method hooking (see @MASTG-TECH-0095) to detect text input components such as [`UITextField`](https://developer.apple.com/documentation/uikit/uitextfield). Hook the methods invoked during user interaction and log the user's input.
2. Exercise the app and all text inputs thoroughly

## Observation

The output should contain all strings eligible for keyboard caching.

## Evaluation

The test case fails if the output contains any sensitive strings that are eligible for keyboard caching, such as usernames, passwords, email addresses, or credit card numbers.
