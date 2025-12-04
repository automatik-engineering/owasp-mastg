---
platform: android
title: Determine if Sensitive Data are sent to Firebase Analytics with Frida
id: MASTG-DEMO-00de3
code: [kotlin]
test: MASTG-TEST-02te3
---

## Sample

This sample demonstrates an Android application that sends sensitive user information to Firebase Analytics using the `logEvent` method. The app collects the user's blood type and user ID, which are considered sensitive data (health information), and transmits them to Firebase Analytics.

> Note: We cannot perform this test with static analysis because the parameters sent to Firebase Analytics are constructed dynamically at runtime.

{{ MainActivity.kt # MastgTest.kt # build.gradle.kts.libs }}

## Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Select a blood type from the dropdown
5. Click the **Start** button
6. Stop the script by pressing `Ctrl+C` and/or `q` to quit the Frida CLI

{{ hooks.js # run.sh }}

## Observation

The output shows all instances of `logEvent` calls to Firebase Analytics SDK that were found at runtime, along with the parameters being sent. A backtrace is also provided to help identify the location in the code.

{{ output.json }}

## Evaluation

This test **fails** because sensitive data (`blood_type` parameter) is being sent to Firebase Analytics via the `logEvent` method for a particular user (`user_id` parameter).
