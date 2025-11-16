---
platform: ios
title: Uses of Insecure Random Number Generation with r2
code: [swift]
id: MASTG-DEMO-0063
test: MASTG-TEST-xx63
---

### Sample

The following sample demonstrates the use of insecure random number generation using the C standard library `rand` function, which is not suitable for cryptographic purposes. The sample also shows secure alternatives, in particular `SecRandomCopyBytes`.

This sample demonstrates various methods of generating random tokens, and contrasts insecure and secure approaches. It includes

- Insecure methods using libc `rand`, a custom linear congruential generator LCG, and `drand48`
- Cryptographically secure but lower level or less recommended methods such as direct reads from `/dev/random`, `arc4random`, `arc4random_uniform`, `SystemRandomNumberGenerator`, and `CCRandomGenerateBytes`
- A preferred secure method using `SecRandomCopyBytes`

> Note that `rand` and `srand` are not available directly in Swift. In this demo we use the libc `rand` and `srand` functions by declaring our own bindings to the symbols because they are not included in the Swift standard library anymore.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file, as described in @MASTG-TECH-0058. For this demo the path is `./Payload/MASTestApp.app/MASTestApp`.
2. Run @MASTG-TOOL-0073 on the binary and use the `-i` option to execute the script below.

{{ run.sh # insecure_random.r2}}

This script:

- Uses `ii` to list imported symbols.
- Filters that list with `~+rand` to keep only imports whose names contain `rand`, such as `rand`, `srand`, `drand48`, `arc4random`, and `arc4random_uniform`.
- Uses `[1]` to select the address column from that output.
- Uses `axt @@=...` to run `axt` on each of those addresses and print cross references to the corresponding calls.

### Observation

The output of the script shows cross references to calls to functions whose names contain `rand` in the sample binary.

{{ output.txt }}

This output contains both insecure and secure APIs. For this test case the interesting calls are:

- `sym.imp.rand` and `sym.imp.srand`, which expose the insecure libc PRNG.
- `sym.imp.drand48`, which also uses an insecure linear congruential generator.

The same output also shows calls to secure sources such as `SecRandomCopyBytes`, `CCRandomGenerateBytes`, `SystemRandomNumberGenerator`, and the Swift `FixedWidthInteger.random` implementation. These are present in the sample for contrast, but they are not the reason the test fails.

### Evaluation

The test fails because insecure PRNGs are used in a security relevant context:

- `rand` is seeded with the current time in `mastgTest`, through the call to `c_srand`
- `generateInsecureRandomTokenRand` uses `c_rand` to generate bytes for a token string
- `drand48` is used in `generateInsecureRandomTokenDrand48` to generate another token
- Both tokens are presented as random tokens that could be used for security sensitive purposes

When you decompile or disassemble the functions reported by `axt` you should confirm that random values from `rand` and `drand48` are used to construct tokens. In this demo those tokens are explicitly labeled as random tokens and are intended to simulate security relevant values such as authentication tokens or identifiers.

The sample also contains several secure or acceptable sources of random data which pass the test, including:

- `SystemRandomNumberGenerator` and Swift `UInt8.random` which are backed by the system CSPRNG
- Direct reads from `/dev/random`
- `arc4random` and `arc4random_uniform`
- `CCRandomGenerateBytes`
- `SecRandomCopyBytes`

These are included to highlight the difference between insecure and secure generators in the same binary and to produce realistic output where `axt` finds both kinds of APIs.

For security critical operations, such as generating cryptographic keys, IVs, nonces, authentication tokens, or passwords, you should avoid libc PRNGs such as `rand`, `random`, and the `*rand48` family. On iOS the recommended approach in this context is to use `SecRandomCopyBytes` or higher level APIs built on top of the system CSPRNG.
