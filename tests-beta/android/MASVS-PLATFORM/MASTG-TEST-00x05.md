---
platform: android
title: Sensitive Data Leaked via Notifications
id: MASTG-TEST-00x05 // TODO replace with real ID
apis: [NotificationManager]
type: [static, dynamic]
weakness: MASWE-0054
prerequisites:
- identify-sensitive-data
profiles: [L1, L2]
---

## Overview

This test case checks if the application leaks sensitive data via notifications to third parties.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis tool such as @MASTG-TOOL-0110 on the reverse-engineered app to identify if the `POST_NOTIFICATIONS` permission is declared in the manifest file (for above Android API 33). This would indicate that the app creates notifications.
2. Run a static analysis tool such as @MASTG-TOOL-0110 on the app source, or run the app and use a dynamic analysis with @MASTG-TECH-0033 and a tool like @MASTG-TOOL-0001 and start tracing all calls to functions related to the notifications creation, e.g. `setContentTitle` or `setContentText` from [`Notification.Builder`](https://developer.android.com/reference/android/app/Notification.Builder) or[`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder).

## Observation

The output should contain:

 - the `POST_NOTIFICATIONS` permission, if declared in the manifest file, and
 - a list of locations where notification APIs are used.

## Evaluation

The test case fails if sensitive data is found to be contained in any notification created by the app.
