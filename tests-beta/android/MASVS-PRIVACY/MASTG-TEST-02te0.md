---
platform: android
title: Use of Third-Party Tracking & Analytics SDKs
id: MASTG-TEST-02te0
type: [manual]
weakness: MASWE-0112
profiles: [P]
---

## Overview

This test verifies whether an app uses tracking or analytics SDKs.

## Steps

1. Use @MASTG-TECH-0130 or @MASTG-TECH-0131 to generate an SBOM.

## Observation

The output should contain a list of the embedded/3rd-party libraries used in the app.

## Evaluation

Evaluate those libraries online or their codebase for their purpose. The test case fails if any of the libraries are used for tracking or analytics purposes. If no such libraries are found, the test case passes.

> TIP: If they are free & open source libraries, you may search their codebase such as by looking for permissions like `INTERNET` or `ACCESS_NETWORK_STATE` in their manifest files, or check their documentation for network-related features as network access is typically required for tracking or analytics SDKs to send data to their servers.
