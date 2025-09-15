---
platform: ios
title: Monitor secrets in logs
code: [swift]
id: MASTG-DEMO-0023
test: MASTG-TEST-0024
---

### Sample

The code snippet below shows sample code that logs a sensitive token.

{{ ../MASTG-DEMO-0024/MastgTest.swift }}

### Steps

1. Install the app on a device (@MASTG-TECH-0056)
2. Make sure you have @MASTG-TOOL-0126 installed on your machine
3. Run `run.sh` to start the log capturing
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C` to end the log capturing

{{ run.sh }}

### Observation

The output contains all device logs, including the logged strings from the app.

{{ output.txt }}

### Evaluation

The test fails because we can see `TOKEN=123` inside the logs at:

```text
MASTestApp(Foundation)[94322] <Notice>: NSLog: Leaking TOKEN=123 from NSLog
MASTestApp[94322] <Error>: logger.warning: Leaking TOKEN=123
MASTestApp[94322] <Error>: logger.error: Leaking TOKEN=123
```
