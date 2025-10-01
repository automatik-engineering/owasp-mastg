---
platform: android
title: Sensitive Data Leaked via Embedded Libraries
id: MASTG-TEST-xxxx // TODO
type: [static, dynamic]
weakness: MASWE-xxxA // TODO see https://github.com/OWASP/maswe/pull/11
prerequisites:
  - identify-sensitive-data
profiles: [L1, L2]
---

## Overview

This test case focuses on identifying potentially sensitive data that may have been inadvertently leaked through embedded third-party libraries used by the application. For example, an app might use a third-party analytics SDK to track user behavior. Still, if the SDK is not correctly configured, it could inadvertently send sensitive information (like PIIs - Personal Identifiable Information, or secrets) to that third-party service.

## Steps

To investigate this, you have two options:

### Method 1

1. Use @MASTG-TOOL-0001 to hook all network functions (and try to detect PII or secrets in their calls). Use the backtraces to find out which component is sending what PII or secrets. This should also include the corresponding network domains. It should provide excellent coverage while staying sufficiently generic.

### Method 2

1. Identify the package name of the embedded library you wish to run the test against, or the list of package names of embedded libraries, by generating an SBOM.
    - (optional) To generate an SBOM, you can use tools like @MASTG-TOOL-0130 or @MASTG-TOOL-0134 with @MASTG-TECH-0130 or @MASTG-TECH-0131 to identify all embedded/3rd-party libraries used by the app. You may consult @MASTG-TECH-0130. Shortlist the embedded/3rd-party libraries' APIs that have network functionality and that should not handle sensitive information. You can research those libraries online or their codebase to see if they have network functionality. Look for permissions like `INTERNET` or `ACCESS_NETWORK_STATE` in their manifest files, or check their documentation for network-related features.
2. Identify common APIs of the library/these libraries that are used to send data to their servers. Use @MASTG-TECH-0110, potentially with @MASTG-TOOL-0108, to identify the entry points where sensitive data may be passed to the APIs. You can research those libraries online or their codebase for entry points. The entry points would be "package name" plus "method path and name". For example, if the library is `com.example.analytics` and it has a method `trackEvent(String eventName, Map<String, String> properties)`, then the entry point would be `com.example.analytics.trackEvent`.

## Observation

The output should contain a list of locations where sensitive information is passed to embedded/3rd-party libraries or a list of network requests to third-party servers that contain sensitive information.

## Evaluation

The test case fails if sensitive data is passed to embedded/3rd-party libraries that have network functionality, or if network requests to third-party servers contain sensitive information.
