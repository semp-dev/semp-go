# SEMP Cryptographic Audit Report

**Date:** April 2026
**Scope:** Protocol specification (semp-spec) and reference implementation (semp-go v0.2.5)
**Auditor:** Automated structural review. Not a formal cryptographic audit. Does not replace review by a professional cryptography firm.

---

## Status: ALL FINDINGS RESOLVED

Resolved in semp-go v0.3.0 (April 2026).

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | |
| High | 1 | RESOLVED: constant-time hash comparison |
| Medium | 4 | RESOLVED: AAD on AEAD, hybrid PQ wrapping, rekey labels, key zeroization |
| Low | 4 | RESOLVED: Argon2id params, at-rest AAD, rekey transition, signature domain separation |
| Informational | 5 | Positive findings (no action needed) |

---

## High Severity

### H1: Non-Constant-Time Confirmation Hash Comparison

**File:** `handshake/server.go:582-592`, `handshake/federation.go:960`

The `bytesEqual` function uses a byte-by-byte loop that short-circuits on first mismatch. This is used to compare the confirmation hash in `OnConfirm`. An attacker who can measure response timing could theoretically brute-force the expected confirmation hash one byte at a time.

The codebase already uses `crypto/subtle.ConstantTimeCompare` in `crypto/mac.go:Verify`, so the correct primitive is available.

**Recommendation:** Replace `bytesEqual` with `subtle.ConstantTimeCompare`.

---

## Medium Severity

### M1: No AAD on Brief and Enclosure AEAD Encryption

**File:** `envelope/compose.go:100, 115`

The brief and enclosure are encrypted with `aead.Seal(key, nonce, plaintext, nil)`. The additional authenticated data is nil. This means the encrypted brief blob is not cryptographically bound to the envelope it belongs to. An attacker who obtains K_brief (e.g., as a legitimate recipient) could transplant the encrypted brief from one envelope into another.

The seal signature and session MAC cover the envelope as a whole (including the base64 brief blob), which provides integrity. However, the AEAD itself provides no binding. In contrast, the identity proof encryption in the handshake correctly uses `sessionID` as AAD.

**Recommendation:** Pass a binding context as AAD, such as `postmark.id` or a hash of the postmark.

### M2: Per-Recipient Key Wrapping Uses Only X25519, Not PQ-Hybrid

**File:** `seal/wrap.go:58-67, 86-88`

The `Wrapper` always uses plain X25519 for per-recipient key wrapping, regardless of the session suite. K_brief and K_enclosure are wrapped under classical X25519 only. A harvest-now-decrypt-later attacker who records encrypted envelopes and later gains quantum capability can recover K_brief and K_enclosure from the seal's recipient maps, even though the session key exchange is PQ-protected.

The session MAC (K_env_mac) is protected by PQ forward secrecy, but the symmetric envelope keys themselves are not.

**Recommendation:** Define hybrid recipient encryption keys (X25519 + Kyber768) in the key publication spec and use hybrid wrapping for brief_recipients and enclosure_recipients. Until then, document that PQ protection applies only to session-level forward secrecy, not to at-rest envelope confidentiality.

### M3: Rekey Derivation Uses Same HKDF Info Labels as Initial Session

**File:** `crypto/kdf.go:152-158`

`DeriveRekeyKeys` delegates directly to `DeriveSessionKeys`, using the same five HKDF info labels. The spec (SESSION.md section 3.3) defines a distinct info context `"SEMP-v1-rekey"`, and the `InfoRekey` constant is defined but never used in any derivation. Context separation relies solely on different IKM and salt values.

**Recommendation:** Either use `InfoRekey` as a prefix for the five per-key labels during rekey, or document that context separation comes solely from IKM/salt distinctness.

### M4: No Zeroization of Derived Key in At-Rest Encryption

**File:** `store/encrypt.go:41, 66`

The AES key derived from Argon2id is never zeroized after use. The `crypto.Zeroize` function exists and is used elsewhere, but the store package does not call it. The derived key remains in memory until garbage-collected.

**Recommendation:** Add `defer crypto.Zeroize(key)` after `DeriveKey` returns in both `EncryptPrivateKey` and `DecryptPrivateKey`.

---

## Low Severity

### L1: Argon2id Memory Parameter is at the Floor

**File:** `store/encrypt.go:14-18`

Parameters: memory=64 MiB, iterations=3, parallelism=4. While not critically weak, these are at the low end of current recommendations for protecting high-value private keys.

**Recommendation:** Consider increasing to memory=128 MiB, iterations=4, or make parameters configurable.

### L2: No AAD in AES-256-GCM At-Rest Encryption

**File:** `store/encrypt.go:56`

`gcm.Seal(nil, nonce, plaintext, nil)` passes nil AAD. An attacker with write access to the key store could swap encrypted key entries between slots without detection.

**Recommendation:** Pass a context identifier as AAD (e.g., key_id or key_type concatenation).

### L3: Session Key Erasure During Rekey Transition Window

**File:** `session/session.go:ApplyRekey:188-202`

Old session keys are erased before the 5-second transition window expires. In-flight envelopes referencing the old session ID during this window will fail MAC verification because K_env_mac has been erased.

**Recommendation:** Retain the old K_env_mac (only) for the transition window duration, or document that in-flight envelopes may be rejected during rekey.

### L4: No Ed25519 Signature Domain Separation

**File:** `handshake/server.go`, `envelope/compose.go`

The same Ed25519 domain key signs handshake messages, envelope seals, key responses, and discovery responses without a domain-separation prefix. In theory, a crafted canonical message in one context could collide with another.

**Recommendation:** Add domain-separation prefixes (e.g., `"SEMP-HANDSHAKE:" || bytes` vs `"SEMP-ENVELOPE:" || bytes`).

---

## Informational (Positive Findings)

### I1: Identity Binding is Correct

The server's identity proof signs `eph_pub || server_nonce || client_nonce` under the domain key. The client's identity proof signs `session_id || confirmation_hash` under the identity key, encrypted with session_id as AAD. Identity misbinding attacks are prevented.

### I2: Downgrade Protection is Correct

The confirmation hash covers the full init and response messages including capability negotiation. Suite tampering causes a hash mismatch. The hash uses the fixed primitive SHA-256.

### I3: Nonce Reuse is Impossible by Construction

K_brief and K_enclosure are fresh random keys per envelope. Even a nonce collision is harmless under distinct keys. The wrap key uses a fresh ephemeral DH per call.

### I4: Hybrid KEM Concatenation is Consistent

IKM ordering is always `K_kyber || K_x25519` across encapsulate, decapsulate, and the helper function. Wire format is consistent. No ordering ambiguity.

### I5: Zeroize Uses Anti-Elision Pattern

`Zeroize` uses explicit loop + `runtime.KeepAlive` to prevent dead-store elimination. Used consistently across ephemeral keys, shared secrets, PRK values, and symmetric keys.

---

## Architectural Observation

The most significant architectural decision is that PQ protection (Kyber768) applies only to session key exchange, not to per-recipient envelope key wrapping. This means envelope confidentiality at rest is protected only by classical X25519. A quantum adversary who records envelopes today can decrypt them when quantum computers become available. The session-level PQ protection prevents real-time interception but does not protect stored messages. Extending PQ protection to the seal layer requires hybrid recipient encryption keys, which is a protocol-level change.
