---
platform: ios
title: References to APIs for Preventing Keyboard Caching of Text Fields
id: MASTG-TEST-0313
type: [static]
weakness: MASWE-0053
---

## Overview

This test verifies whether the target app prevents sensitive information entered into text fields from being cached. On iOS, the keyboard may suggest previously entered text when typing in any app on the device.

The test checks whether the app instructs the system **not** to cache user input for a given text field by setting [`UITextAutocorrectionType.no`](https://developer.apple.com/documentation/uikit/uitextautocorrectiontype/no).

**Note:** By default, text input is cached, and an app does not need to explicitly set `UITextAutocorrectionType` when creating a text field. Additionally, the UI may be configured in a Storyboard. As a result, this test may miss many true positives. For complete coverage, using @MASTG-TEST-0314 is recommended.

Any of the following attributes, if present, will prevent the caching mechanism for text inputs:

- [`UITextAutocorrectionType.no`](https://developer.apple.com/documentation/uikit/uitextautocorrectiontype/no)
- [`secureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry)

Check whether UI elements such as `UITextField`, `UITextView`, and `UISearchBar` use the `UITextAutocorrectionType.no` attribute.

## Steps

1. Use @MASTG-TECH-0065 to reverse engineer the app.
2. Use @MASTG-TECH-0072 to look for uses of the functions that set these attributes.
3. Use @MASTG-TECH-0076 to analyze the relevant code paths and obtain the values assigned to these attributes.

## Observation

The output should indicate whether the app uses no-caching attributes.

## Evaluation

The test case fails if none of the text fields in your app use no-caching attributes, as this indicates the app may not be aware of keyboard caching.
