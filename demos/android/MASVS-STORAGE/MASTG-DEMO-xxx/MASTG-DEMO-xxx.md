---
platform: android
title: App Leaking Sensitive Data via Notifications
id: MASTG-DEMO-xxx // TODO replace with real ID
code: [kotlin]
test: MASTG-TEST-00x05 // TODO replace with real ID
tools: [MASTG-TOOL-0110]
---

### Sample

The following samples contain:
- the Kotlin code that creates a notification with sensitive data.
- the AndroidManifest.xml with a `POST_NOTIFICATIONS` permission to post notifications (for above Android API 33).

{{ MastgTest.kt # AndroidManifest.xml }}

### Steps

1. Install an app on your device.
2. Execute `run_before.sh` which grants runtime notification permission.
3. Let's run our @MASTG-TOOL-0110 rule against the sample code.
4. And another one against the sample manifest file.
5. Execute `run_after.sh` to revoke the runtime notification permission.
6. Close the app once you finish testing.

{{ run_before.sh }}
{{ ../../../../rules/mastg-android-sensitive-data-in-notifications.yml }}
{{ ../../../../rules/mastg-android-sensitive-data-in-notifications-manifest.yml }}
{{ run.sh }}
{{ run_after.sh }}

### Observation

TODO 

### Evaluation

TODO