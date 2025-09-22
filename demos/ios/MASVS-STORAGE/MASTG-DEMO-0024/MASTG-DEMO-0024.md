---
platform: ios
title: Uses of logging APIs with r2
code: [swift]
id: MASTG-DEMO-0x53
test: MASTG-TEST-0024
---

### Sample

The code snippet below shows sample code that logs a sensitive token using different [logging APIs](../../../../Document/0x06d-Testing-Data-Storage/#logs).

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh` to find all occurrences of `NSLog`.
3. Repeat the same steps as in `run.sh` using another such as e.g. `print`.

{{ loggingApi.r2 }}

{{ run.sh }}

### Observation

The output contains the location of `NSLog` usage in the binary.

{{ output.asm }}

Reading `output.asm` doesn't clearly show what arguments are passed to `NSLog`, so you can also make use of `function.asm` for a better overview.

### Evaluation

The test fails because it calls `NSLog` with the secret token as an argument.
