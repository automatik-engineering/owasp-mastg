---
platform: ios
title: Runtime Monitoring of Text Fields Eligible for Keyboard Caching
id: MASTG-TEST-0314
type: [dynamic]
weakness: MASWE-0053
---

## Overview

This test is designed to complement @MASTG-TEST-0313. It monitors all text inputs in the app at runtime (e.g., [`UITextField`](https://developer.apple.com/documentation/uikit/uitextfield)) and lists every field into which the user has entered text. After each interaction, it reports whether the input is protected against keyboard caching. Therefore, it is important to exercise the app thoroughly.

For example, you can use a Frida script that hooks into relevant UIKit methods and monitoring interactions with text inputs (for example, `UITextField` and `UITextView`).

## Steps

1. Use @MASTG-TECH-0056 to install the app.
2. Use @MASTG-TECH-0067 to look for text input fields in the app's UI and identify those that use the relevant attributes.
3. Exercise the app thoroughly ensuring that you enter sensitive information (for example, usernames, passwords, email addresses, credit card numbers, recovery codes) into various text fields.
4. Stop the monitoring and collect the script output for analysis.

## Observation

The output should contain:

- Strings entered by the user.
- The input widgets (class, accessibility identifier when available).
- Report protection attributes relevant to keyboard caching, such as `isSecureTextEntry` and related input traits.

## Evaluation

The test fails if any sensitive strings (for example, usernames, passwords, email addresses, credit card numbers, recovery codes) are entered into inputs that are eligible for keyboard caching (not protected). If all sensitive entries occur only in protected inputs (for example, `isSecureTextEntry` enabled), the test passes.
