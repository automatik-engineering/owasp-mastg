---
platform: android
title: App Leaking Sensitive Data via Notifications
id: MASTG-DEMO-xxx // TODO replace with real ID
code: [kotlin]
test: MASTG-TEST-00x05 // TODO replace with real ID
tools: [MASTG-TOOL-0110]
---

### Sample

The following sample code contains:

- the Kotlin code that creates a notification with the `NotificationManager` class and exposes sensitive data.
- the AndroidManifest.xml with a `POST_NOTIFICATIONS` permission to post notifications (for above Android API 33).

{{ MastgTest.kt # AndroidManifest.xml }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the reversed java code.

{{ ../../../../rules/mastg-android-sensitive-data-in-notifications.yml }}

And another one against the sample manifest file.

{{ ../../../../rules/mastg-android-sensitive-data-in-notifications-manifest.yml }}

{{ run.sh }}

### Observation

The rule detected 2 instances in the code where the `setContentTitle` API is used to set the notification title, and 2 instances where the `setContentText` API is used to set the notification text. It also identified the location in the manifest file where the POST_NOTIFICATIONS permission is declared.

{{ output.txt # output2.txt }}

### Evaluation

After reviewing the decompiled code at the location specified in the output (file and line number) we can conclude that the test fails because the file written by this instance contains sensitive data, specifically a first and a last name (PII).
