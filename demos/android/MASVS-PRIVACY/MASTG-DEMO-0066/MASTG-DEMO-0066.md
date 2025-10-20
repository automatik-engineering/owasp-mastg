---
platform: android
title: App Exposing Sensitive Information to Firebase Analytics
id: MASTG-DEMO-0066
code: [kotlin]
test: MASTG-TEST-0297
---

## Sample

This sample demonstrates an Android application that inadvertently leaks sensitive user information to Firebase Analytics. The app collects various types of sensitive data, such as user IDs, email addresses, and names, and sends this information to Firebase Analytics.

{{ MastgTest.kt # build.gradle.kts.libs }}

## Steps

Let's run our @MASTG-TOOL-0110 rule against the reversed Java code.

{{ ../../../../rules/mastg-android-sensitive-data-to-embedded-firebase-analytics.yml }}

{{ run.sh }}

## Observation

The rule detected 8 instances where sensitive data might be sent to Firebase Analytics. The findings include various types of sensitive information, such as user IDs, email addresses, and names, based on the rule's defined pattern.

{{ output.txt }}

## Evaluation

After reviewing the decompiled code at the location specified in the output (file and line number), we can conclude that the test fails because the file written by this instance contains sensitive information, specifically a first and a last name, an email, a user ID, and a secret.
