---
platform: ios
title: Runtime Tracking of Files Eligible for Backup
id: MASTG-TEST-0298
type: [dynamic]
weakness: MASWE-0004
best-practices: [MASTG-BEST-0023]
profiles: [L1, L2, P]
---

## Overview

This test logs every file written to the app's data container at `/var/mobile/Containers/Data/Application/$APP_ID` to identify which files are eligible for backup. Files stored in the `tmp` or `Library/Caches` subdirectories are not logged, as they are never backed up.

## Steps

1. Install the app on a device (@MASTG-TECH-0056)
2. Make sure you have @MASTG-TOOL-0039 installed
3. Begin tracking every file the app opens
4. Open the app
5. Navigate to the mobile app which you wish to analyze
6. Close the app

## Observation

The output should list every file that the app opens and that is eligible for backup.

## Evaluation

The test case fails if you can find sensitive files inside the output.
