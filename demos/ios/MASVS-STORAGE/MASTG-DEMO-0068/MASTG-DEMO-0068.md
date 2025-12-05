---
platform: ios
title: Runtime Monitoring of Text Fields Eligible for Keyboard Caching with Frida
id: MASTG-DEMO-0068
code: [swift]
test: MASTG-TEST-0x55-2
---

### Sample

The code snippet below creates multiple UI text inputs on the screen.

{{ MastgTest.swift }}

### Steps

1. Install the app on a device (@MASTG-TECH-0056).
2. Make sure you have @MASTG-TOOL-0039 installed on your machine and the frida-server running on the device.
3. Run `run.sh` to spawn your app with Frida.
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C`

{{ run.sh # script.js }}

### Observation

{{ output.txt }}

The output contains all text that the user entered in every text input, along with its keyboard-cache eligibility.

### Evaluation

The test fails because the output shows user's sensitive input "first sensitive input" in one of the text fields and is eligible for caching.

```txt
Eligible for caching [autocorrectionType=.default, secure=false, class=_UIAlertControllerTextField]: "first sensitive input"
```
