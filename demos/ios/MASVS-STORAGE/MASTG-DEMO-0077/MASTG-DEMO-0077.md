---
platform: ios
title: Runtime Monitoring of Text Fields Eligible for Keyboard Caching with Frida
id: MASTG-DEMO-0077
code: [swift]
test: MASTG-TEST-0x55-2
---

### Sample

This demo uses the same sample as @MASTG-DEMO-0076.

{{ ../MASTG-DEMO-0076/MastgTest.swift }}

### Steps

1. Install the app on a device (@MASTG-TECH-0056).
2. Make sure you have @MASTG-TOOL-0039 installed on your machine and the frida-server running on the device.
3. Run `run.sh` to spawn your app with Frida.
4. Click the **Start** button.
5. Stop the script by pressing `Ctrl+C`.

{{ run.sh # script.js }}

### Observation

{{ output.txt }}

The output contains all text that the user entered in every text input, along with its keyboard-cache eligibility.

### Evaluation

The test fails because the output shows the user's sensitive input "first sensitive input" in one of the text fields and it is eligible for caching.

```txt
Eligible for caching [autocorrectionType=.default, secure=false, class=_UIAlertControllerTextField]: "first sensitive input"
```
