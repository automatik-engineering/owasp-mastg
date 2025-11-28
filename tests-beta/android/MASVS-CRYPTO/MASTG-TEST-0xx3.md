---
platform: android
title: References to Reused Initialization Vectors in Symmetric Encryption
id: MASTG-TEST-0xx3
type: [static]
weakness: MASWE-0022
status: placeholder
profiles: [L2]
note: Reusing a symmetric key is normal, but only when IVs or nonces follow the rules of the mode. CBC needs fresh or unpredictable IVs. Stream and counter-based modes need nonces that never repeat under the same key. Repeated key and nonce pairs break confidentiality and often integrity.
---
