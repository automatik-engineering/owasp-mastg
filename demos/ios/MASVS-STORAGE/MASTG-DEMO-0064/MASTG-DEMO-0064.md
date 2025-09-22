---
platform: ios
title: Monitor secrets in logs
code: [swift]
id: MASTG-DEMO-0064
test: MASTG-TEST-0296
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
Sep 22 11:20:31 MASTestApp(Foundation)[32240] <Notice>: NSLog: Leaking TOKEN=123 from NSLog
Sep 22 11:20:31 MASTestApp[32240] <Error>: logger.warning: Leaking <private>
Sep 22 11:20:31 MASTestApp[32240] <Error>: logger.warning (privacy: .public): Leaking TOKEN=123
Sep 22 11:20:31 MASTestApp[32240] <Error>: logger.error (privacy: .public): Leaking TOKEN=123
Sep 22 11:20:31 MASTestApp[32240] <Fault>: logger.fault (privacy: .public): Leaking TOKEN=123
```
