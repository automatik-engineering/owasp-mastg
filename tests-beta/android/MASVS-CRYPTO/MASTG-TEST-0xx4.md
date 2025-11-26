---
platform: android
title: Runtime Use of Reused Initialization Vectors in Symmetric Encryption
id: MASTG-TEST-0xx4
type: [dynamic]
weakness: MASWE-0012
status: placeholder
profiles: [L1, L2, P]
note: Reusing a symmetric key is normal, but only when IVs or nonces follow the rules of the mode. CBC needs fresh or unpredictable IVs. Stream and counter based modes need nonces that never repeat under the same key. Repeated key and nonce pairs break confidentiality and often integrity.
---
