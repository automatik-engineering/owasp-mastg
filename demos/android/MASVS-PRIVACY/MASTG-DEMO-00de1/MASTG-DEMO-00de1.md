---
platform: android
title: Uses of Firebase Analytics APIs on Potential PII with semgrep
id: MASTG-DEMO-00de1
code: [kotlin]
test: MASTG-TEST-02te1
---

## Sample

This sample demonstrates an Android application sending data to Firebase Analytics.

{{ MastgTest.kt # build.gradle.kts.libs }}

## Steps

Let's run our @MASTG-TOOL-0110 rule against the reversed Java code.

{{ ../../../../rules/mastg-android-usage-of-firebase-analytics.yml }}

{{ run.sh }}

## Observation

The rule detected one instance where sensitive data might be sent to Firebase Analytics.

{{ output.txt }}

## Evaluation

After reviewing the decompiled code at the location specified in the output (file and line number), we can conclude that the test fails because the app is using the Firebase Analytics SDK.

> Note: Since user input sent to Analytics is dynamic, we have no indication of whether the data being sent is actually sensitive. This evaluation is out of scope for this demo.