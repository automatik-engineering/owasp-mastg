---
platform: android
title: App Exposing User Authentication Data in Text Input Fields
id: MASTG-TEST-02te
type: [static, manual] // TODO evaluate
weakness: MASWE-0053
profiles: [P]
---

## Overview

This test verifies that the app handles user input correctly, ensuring that access codes (passwords or pins) and verification codes (OTPs) are not exposed in plain text within text input fields.

Proper masking (dots instead of input characters) of these codes is essential to protect user privacy. This can be achieved by using appropriate input types that obscure the characters entered by the user.

XML view:

```xml
<EditText
    android:inputType="textPassword"
    ...
/>
```

Jetpack Compose:

```kotlin
SecureTextField(
    textObfuscationMode = TextObfuscationMode.RevealLastTyped, // or TextObfuscationMode.Hidden
    ...
)
```

> Note: That even if the SecureTextField is used with `textObfuscationMode` set to `RevealLastTyped` or `Hidden`, it can later be changed to `Visible` programmatically.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis tool such as @MASTG-TOOL-0110 on the reverse-engineered app's source code to identify the usage of the text field APIs.
3. Manually evaluate and shortlist the fields for access or verification codes usage.

## Observation

The output should contain a list of locations where text input fields for access or verification codes are used.

## Evaluation

The test case fails if access or verification codes are found in the text input fields unmasked.
