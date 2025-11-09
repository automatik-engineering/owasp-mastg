---
platform: ios
title: Differential Analysis of Files and Keychain Entries Created at Runtime
id: MASTG-TEST-0x52-3
type: [dynamic, filesystem]
prerequisites:
- identify-sensitive-data
profiles: [L2]
weakness: MASWE-0006
best-practices: [MASTG-BEST-00xx]
---

## Overview

This test is designed to complement @MASTG-TEST-0x52-2. Instead of monitoring APIs during execution, it performs a differential analysis of the app's Private Storage by comparing snapshots taken before and after exercising the app. It also enumerates Keychain items created or modified during the session.

The goal is to identify new or modified files and determine whether they contain sensitive data in plaintext or trivially encoded form, and to identify new Keychain entries that may contain sensitive data or keys used for file encryption.

## Steps

1. Ensure the device / simulator is in a clean state (no prior test artifacts). Terminate the app if running.
2. Take an initial snapshot of the app's Private Storage (sandbox) directory tree (@MASTG-TECH-0052). Record: paths, sizes, modification times, hashes (e.g., SHA-256).
3. Launch and exercise the app to trigger typical workflows (authentication, profile loading, messaging, caching, offline usage, cryptographic operations).
4. Take a second snapshot of the Private Storage directory tree.
5. Diff the two snapshots to identify new, deleted, and modified files. For modified files, determine whether content changes involve potential sensitive values.
6. Enumerate Keychain items added or modified during the session using @MASTG-TECH-0061. Optionally record attributes (accessible class, access control flags, etc).
7. Inspect new or changed files:
    - Attempt safe decoding of content that appears encoded (Base64, hex, URL-encoded, plist, JSON, property list, compressed archives like ZIP, SQLite, Core Data stores).
    - For binary formats (e.g., SQLite DB), query schema for tables/fields that may contain tokens, credentials, identifiers.

## Observation

The output should contain:

- List of new or modified files with: path, size, hash, inferred type, encoding/encryption status (plaintext / encoded / encrypted / unknown).
- List of new or modified Keychain entries.

## Evaluation

The test case fails if sensitive data appears in plaintext or trivially encoded in new or modified files.

Attempt to identify and decode data that has been encoded using methods such as base64 encoding, hexadecimal representation, URL encoding, escape sequences, wide characters and common data obfuscation methods such as xoring. Also consider identifying and decompressing compressed files such as tar or zip. These methods obscure but do not protect sensitive data.
