---
platform: android
title: App Exposing Sensitive Data via Notifications
id: MASTG-TEST-00x05 // TODO replace with real ID
apis: [NotificationManager]
type: [static, dynamic]
weakness: MASWE-0054
prerequisites:
- identify-sensitive-data
profiles: [P]
---

## Overview

This test verifies that the app handles notifications correctly, ensuring that sensitive information—such as personally identifiable information (PII), one-time passwords (OTPs), or other sensitive data like health or financial details—is not exposed. On Android, developers typically request the runtime permission `POST_NOTIFICATIONS` that allows the app to send notifications. The creation of notifications can be handled through [`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder) or `setContentTitle` or `setContentText` from [`Notification.Builder`](https://developer.android.com/reference/android/app/Notification.Builder).

The usage of notifications shouldn't expose sensitive information that might otherwise be accidentally disclosed via e.g. shoulder surfing or sharing the device with another person.

// TODO conclude if L2 profile applies here and how other apps could breach confidentiality and read notifications

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis tool such as @MASTG-TOOL-0110 on the reverse-engineered app to identify if the `POST_NOTIFICATIONS` permission is declared in the manifest file (for the above Android API 33). This would indicate that the app generates notifications.
3. Run a static analysis tool such as @MASTG-TOOL-0110 on the reverse-engineered app's source code to identify the usage of the notification APIs, or run the app and use @MASTG-TECH-0033 and a tool like @MASTG-TOOL-0001 and start tracing all calls to functions related to the notifications creation.

## Observation

The output should contain:

- the `POST_NOTIFICATIONS` permission, if declared in the manifest file, and
- a list of locations where notification APIs are used.

## Evaluation

The test case fails if sensitive data is found in any notification created by the app.
