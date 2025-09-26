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
3. Run a static analysis tool such as @MASTG-TOOL-0110 on the reverse-engineered app's source code to identify the usage of the notification APIs, or run the app and use @MASTG-TECH-0033 and a tool like @MASTG-TOOL-0001 and start tracing all calls to functions related to the notifications creation.

## Observation

The output should contain:

- the `POST_NOTIFICATIONS` permission, if declared in the manifest file, and
- a list of locations where notification APIs are used.

## Evaluation

The test case fails if sensitive data is found to be contained in any notification created by the app.
