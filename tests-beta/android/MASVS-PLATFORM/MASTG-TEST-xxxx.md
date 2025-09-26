---
platform: android
title: Sensitive Data Leaked via Embedded Libraries
id: MASTG-TEST-xxxx // TODO
type: [static, dynamic]
weakness: MASWE-xxxA // TODO see https://github.com/OWASP/maswe/pull/11
prerequisites:
  - identify-sensitive-data
  - identify-embedded-libraries-with-network-access // TODO makes sense? get feedback
profiles: [L1, L2]
---

## Overview

This test case focuses on identifying potentially sensitive data inadvertently leaked through embedded third-party libraries used by the application. For example, an app might use a third-party analytics SDK to track user behavior, but if the SDK is not properly configured, it could inadvertently send sensitive information (like PIIs - Personal Identifiable Information, or secrets) to that third-party service.

## Steps

1. Generate an SBOM.
   - For black-box testing, you can use tools like @MASTG-TOOL-0130 or @MASTG-TOOL-0134 with @MASG-TECH-0130 or @MASTG-TECH-0131 to identify all embedded/3rd-party libraries used by the app.
   - For grey/white-box testing, you can manually review the app's build files (like `build.gradle`) to identify dependencies.
2. Shortlist the embedded/3rd-party libraries' APIs which have network functionality and that should not handle sensitive information. Look for permissions like `INTERNET` or `ACCESS_NETWORK_STATE`.
   - For black-box testing, you can research those libraries online or their codebase to see if they have network functionality.
   - For gray/white-box testing, you can manually review the app's merged manifest file in Android Studio or by manually generating with a command like `./gradlew app:processDebugManifest` and then inspecting the file in `app/build/intermediates/merged_manifests/debug/AndroidManifest.xml`. If possible, you can review the app's codebase.
3. Identify common APIs of those libraries that are used to send data to their servers.
   - Use @MASTG-TECH-0110, potentially with @MASTG-TOOL-0108, to identify sensitive data pass to the APIs.
   - Alternatively use you can perform dynamic analysis by intercepting traffic using @MASTG-TECH-0120 and @MASTG-TECH-0121. Once you route the traffic through the interception proxy, you can try to sniff the traffic that passes between the app and app's known servers. All app requests that aren't sent directly to the app's server on which the main function is hosted should be evaluated.

## Observation

The output should contain a list of locations where sensitive information is passed to embedded/3rd-party libraries or a list of network requests to third-party servers that contain sensitive information.

## Evaluation

The test case fails if sensitive data is found to be passed to embedded/3rd-party libraries that have network functionality or if network requests to third-party servers contain sensitive information.




