---
platform: ios
title: Uses of Insecure Random Number Generation with r2
code: [swift]
id: MASTG-DEMO-0063
test: MASTG-TEST-0063
---

### Sample

The following sample demonstrates the use of insecure random number generation using the C standard library `rand()` function, which is not suitable for cryptographic purposes. The sample also shows the secure alternative using `SecRandomCopyBytes`.

{{ MastgTest.swift }}

### Steps

The insecure `rand()` and `srand()` functions from the C standard library are deterministic pseudo-random number generators that produce predictable sequences. These should never be used for security-sensitive operations such as generating tokens, keys, or nonces.

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ insecure_random.r2 }}

{{ run.sh }}

### Observation

The output shows the usage of insecure random functions (`rand`, `srand`) in the binary, including cross-references to where these functions are called and the disassembled code of both the insecure and secure implementations.

{{ output.txt }}

### Evaluation

The test fails because the `rand()` and `srand()` functions were found in the code. These functions are:

- **Predictable**: The sequence of random numbers can be reproduced if the seed value is known
- **Not cryptographically secure**: They use simple linear congruential generator algorithms
- **Deterministic**: Given the same seed, they produce the same sequence of values

In the disassembly, we can identify:
- Calls to `sym.imp.rand` in the `generateInsecureRandomToken` function
- A call to `sym.imp.srand` in the `mastgTest` function to seed the generator
- The secure alternative using `SecRandomCopyBytes` in the `generateSecureRandomToken` function

For security-critical operations, always use `SecRandomCopyBytes` which provides cryptographically secure random numbers from the system's entropy pool.
