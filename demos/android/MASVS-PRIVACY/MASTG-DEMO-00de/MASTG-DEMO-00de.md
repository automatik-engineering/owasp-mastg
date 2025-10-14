---
platform: android
title: App Exposing Access and Verification Codes in Text Input Fields
id: MASTG-DEMO-0033
code: [kotlin]
test: MASTG-TEST-02te
---

### Sample

The following sample code contains the Kotlin code that creates four pairs of username and password input fields in Compose.

{{ MainActivity.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the reversed Java code.

{{ ../../../../rules/mastg-android-input-field-privacy.yaml }}

{{ run.sh }}

### Observation

The rule detected two instances in the code where `TextField` is used and one instance where `SecureTextField` is used.

{{ output.txt }}

### Evaluation

After reviewing the decompiled code at the location specified in the output (file and line number), we can conclude that the test fails because the file written by this instance contains a password field which utilised the `TextField` component instead of the `SecureTextField` component. The test also fails because the `SecureTextField` is used with `textObfuscationMode` set to `TextObfuscationMode.Visible`. We also conclude that the second `TextField` instance (line 80) is a false positive as it's used for a username field and not a password field.