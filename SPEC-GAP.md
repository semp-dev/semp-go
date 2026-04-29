# semp-go Spec Gap

Consolidated catch-up list for bringing `semp-go` current with the SEMP specification at `semp-dev/semp-spec`.

## Baseline

- **Library last spec-sync commit:** `3c13837` (2026-04-13, "Security audit: sanitize error messages, fix session race").
- **Corresponding spec commit (approximate):** `3208899` (2026-04-13, "Add hybrid PQ wrapping, AAD binding, and signature domain separation").
- **Spec HEAD at gap-list time:** `3a9811d` (2026-04-23, "Specify OPTIONAL client-side send-time obfuscation").
- **Commits behind:** 41 spec commits.

The library's README claim of "spec-complete reference implementation" is accurate for its own 2026-04-13 cutoff and no longer holds.

## How to read this document

Each item names the authoritative spec commit that introduced it and the library area that needs change. Items are grouped by impact. Within each group the order is rough suggested implementation sequence. Wire-breaking items come first; additive extensions and new optional modules come later.

`[commit]` references the `semp-spec` commit. `[path]` references the `semp-go` file or package.

---

## 1. Wire-breaking: landing order matters

### 1.1 Reason-code registry ([reasoncodes.go])

- Rename `ReasonPolicyViolation = "policy_violation"` to `ReasonPolicyForbidden = "policy_forbidden"`. `[commit 47c347f]`
- Drop `ReasonChallengeRequired = "challenge_required"`. The spec uses `challenge` as a conditional gate, not a terminal rejection.
- Add handshake codes: `challenge_invalid`, `version_unsupported`. `[47c347f, b0869f8]`
- Add envelope codes: `policy_forbidden`, `envelope_size_exceeded`, `scope_invalid`, `certificate_expired`, `resumption_failed`. `[47c347f, b0869f8, a50cf1c, 4c14bf5]`
- Update `Recoverable()` switch to cover new codes.
- Call sites to update: `handshake/driver.go:141`, `handshake/driver.go:264`, `handshake/capabilities.go:31` all hardcode `"policy_violation"`.

### 1.2 Envelope top-level `padding` field ([envelope/envelope.go])

- Add `Padding string json:"padding"` to the `Envelope` struct. `[commit 2427adb]`
- Canonicalization MUST elide `padding`. Update `EnvelopeElider` in `internal/canonical` and the `CanonicalBytes` doc. The existing test asserts elision of only seal+hop_count; extend it.
- New helper `SelectSizeBucket(n int64) int64` over the sequence `1024, 2048, 4096, ..., max_envelope_size`.
- Compose flow selects bucket and fills `Padding` with fresh random bytes to hit the selected bucket. Iterate-to-convergence is acceptable per `VECTORS.md §3.3`.
- Server side: count `padding` bytes toward `max_envelope_size` enforcement; MUST NOT strip or rewrite `padding` in forwarding.

### 1.3 Recipient-count obfuscation ([seal/], [envelope/compose.go])

`seal.brief_recipients` and `seal.enclosure_recipients` pad to the next power-of-two entry count with dummy entries indistinguishable from real wrapped keys. `[commit 2427adb]`

- Buckets: `1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024`.
- Dummy entry: 32-byte random fingerprint (hex-encoded) plus random ciphertext of the correct length for the negotiated suite.
- Single-domain non-group single-recipient exception per spec `ENVELOPE.md §4.4.1`.
- Compose flow invokes padding before seal signature and session MAC.

### 1.4 First-contact PoW binding ([handshake/pow.go], [reputation/policy.go])

- Bind the `prefix` to `(sender_domain, recipient_address, postmark_id)`. `[commit 47c347f]`
- `prefix = base64(random(16) || SHA-256(sender_domain || recipient_address || postmark_id))`.
- First-contact token schema gains `postmark_id`; drop `hour_bucket`.
- Verification: token's `postmark_id` MUST equal envelope's `postmark.id`. Token is single-use; challenge ledger rejects replay.
- Cross-check: the library's PoW preimage in `handshake/pow.go:30` is `base64(prefix) + ":" + challenge_id + ":" + base64(nonce)`. Spec says `H(prefix || nonce)`. One of the two needs to yield; confirm against current `VECTORS.md §4.3`.

### 1.5 PoW bounds and `challenge_invalid` ([handshake/pow.go])

- Difficulty cap 28 (not 256). `[commit 58b8f9a]`
- Expiry floor by difficulty: `≤20 → 30s`, `21..24 → 60s`, `25..28 → 120s`.
- Initiator aborts with `challenge_invalid` when difficulty exceeds 28 or expiry below floor. Do not retry under same conditions.

### 1.6 Federation collapse ([handshake/federation.go])

The spec collapsed three federation modes (`full`, `relay`, `limited`) into a single mode with per-peer policy. `[commit 594feaf]`

- Remove `FederationType` enum and `FederationFull / FederationRelay / FederationLimited` constants.
- `ServerInit.FederationType` field removed from the wire message.
- Replace with per-peer policy object (definition in current `HANDSHAKE.md §5`).
- Call sites across `handshake/federation.go` and federation tests need updating.

### 1.7 Address canonicalization ([brief/brief.go])

- NFC for local-part (`golang.org/x/text/unicode/norm`). `[commit b0869f8]`
- IDNA2008 A-label for domain (`golang.org/x/net/idna`). ASCII-only on the wire.
- Case-insensitive domain fold to lower case before comparison, signing, hashing.
- 254-octet composed limit.
- Equivalence rule: confusables do NOT collapse; this is protocol, not UX.
- Malformed address at ingress rejects with `policy_forbidden` (existence-oracle-safe).

### 1.8 Sender identity signature on enclosure + forwarding provenance ([enclosure/])

Brand-new surface in the envelope's plaintext layer. `[commit dd798c2]`

- `enclosure.sender_signature`: sender's identity key signs canonical enclosure bytes before encryption.
- `enclosure.forwarded_from`: non-null on forwarded envelopes. Carries `original_enclosure_plaintext` (verbatim, including its own `sender_signature`), `forwarder_attestation` signed by the forwarder's identity key, and metadata (forwarded_from address, received_at).
- Verification chain on receipt: verify new enclosure `sender_signature`, verify `forwarder_attestation`, then verify original `sender_signature`. If step 1 or 3 fail while step 2 passes, rendering rules per `ENVELOPE.md §6.6.4`.

**Integration status (post-commit e511738).** Scaffolding landed: `enclosure.SignEnclosure`, `VerifyEnclosureSignature`, `SignForwarderAttestation`, `VerifyForwarderAttestation`, the `Signature` and `ForwardedFrom` types, and the canonical eliders. Open work that this cluster does NOT yet cover:

- `envelope.Compose` does not invoke `SignEnclosure`. Until it does, every wire envelope this library produces violates `ENVELOPE.md §6.5` (which requires `sender_signature` on every enclosure). `ComposeInput` needs an `IdentityPrivateKey` plus key-id field, and `Compose` MUST sign the enclosure before encryption.
- The decrypt paths (`OpenEnclosure`, `OpenBriefAny`, `OpenEnclosureAny`) do not invoke `VerifyEnclosureSignature` after decryption. Per `ENVELOPE.md §6.5.3`, the recipient client MUST verify before rendering. Open paths need a sender-identity-key resolver hook (typically a callback that maps `sender_signature.key_id` to a public key fetched from `KEY.md §3` published key sets).
- No higher-level helper enforces `ENVELOPE.md §6.6.3`'s rule that `forwarded_from.forwarder_attestation.key_id` MUST equal the outer `enclosure.sender_signature.key_id`. The §6.6.4 three-step verification flow (outer sender → forwarder attestation → original sender) needs a single entry point that returns a structured result (each step's outcome) so client UIs can render the §6.6.4 warning rules.

Track the integration as its own follow-up cluster once a `ComposeInput.IdentityPrivateKey` API decision lands.

### 1.9 Handshake compression removal ([handshake/capabilities.go])

The spec dropped compression from handshake capabilities. `[commit 87e1576]` Check that the library does not advertise or negotiate compression.

### 1.10 Features field migration to extensions ([handshake/message.go], [handshake/capabilities.go])

The library's `Capabilities.Features` and `Negotiated.Features` slices predate the spec's standard capabilities shape. The spec uses `extensions` (an array of extension identifiers) at the capabilities and negotiated layers, distinct from the message-level `extensions` object. Rename the Go fields from `Features` to `Extensions` with JSON tag `extensions`. Intersection logic in `NegotiateCapabilities` preserved; only the field name changes. Update the default capability builders, server and federation-responder construction sites, and tests accordingly.

---

## 2. Signature domain-separation prefixes ([crypto/domainsep.go])

Add these contexts. All go in the single domainsep file.

| Constant | Value | Commit |
|---|---|---|
| `SigCtxDeliveryReceipt` | `SEMP-DELIVERY-RECEIPT:` | `9de2ebb` |
| `SigCtxKeySelfSig` | `SEMP-KEY-SELF-SIG:` | `b0869f8` |
| `SigCtxRecoveryBundle` | `SEMP-RECOVERY-BUNDLE:` | `b0869f8` |
| `SigCtxRecoveryManifest` | `SEMP-RECOVERY-MANIFEST:` | `b0869f8` |
| `SigCtxRecoveryShare` | `SEMP-RECOVERY-SHARE:` | `b0869f8` |
| `SigCtxSuccessorRecord` | `SEMP-SUCCESSOR-RECORD:` | `b0869f8` |
| `SigCtxMigrationRecord` | `SEMP-MIGRATION-RECORD:` | `b0869f8` |
| `SigCtxDeviceRegister` | `SEMP-DEVICE-REGISTER:` | `8db34b4` |
| `SigCtxDeviceAuthorize` | `SEMP-DEVICE-AUTHORIZE:` | `8db34b4` |
| `SigCtxDeviceRevocation` | `SEMP-DEVICE-REVOCATION:` | `8db34b4` |
| `SigCtxDeviceDirectory` | `SEMP-DEVICE-DIRECTORY:` | `8db34b4` |

---

## 3. New packages

### 3.1 `recovery/` Account Recovery

`[commit ee9fd37, 47c347f]`

- Server-assisted encrypted backup bundle (`SEMP_RECOVERY_BUNDLE`).
- Recovery secret derivation (Argon2id with specified parameters).
- Shamir device-split backup with `M of N` threshold.
- `SEMP_RECOVERY_SET_MANIFEST` signed by user identity; binds each `share_index` to a specific `device_id` and `device_identity_pubkey`.
- `SEMP_RECOVERY_SHARE` with `device_id` field and device-key signature (not user-key signature).
- Restore flow: verify manifest, verify each share's device signature against the manifest's pubkey, Lagrange interpolate over `M` valid shares.
- Successor record (`SEMP_SUCCESSOR`) with three signatures (recovery, new_key, domain), all under `SEMP-SUCCESSOR-RECORD:` prefix.
- Cross-check contributor `device_identity_pubkey` against the device directory (package `keys`).

### 3.2 `migration/` Provider Migration

`[commit 3862795, b0869f8]`

- `SEMP_MIGRATION` record with four signatures (`old_identity_signature`, `new_identity_signature`, `new_domain_signature`, `old_domain_signature`).
- Sequential sign-and-embed pattern: each signature covers record plus all prior signatures.
- All four signatures use `SEMP-MIGRATION-RECORD:` prefix; differentiated by signing key.
- Validate `migrated_at ≥ old_identity_key.created` and within clock-skew tolerance.
- Forwarding window (old provider forwards to new for bounded time).
- Cooperative vs unilateral mode.
- Third-party verification per `MIGRATION.md §7.5`.

### 3.3 `closure/` Account Closure

`[commit 9a9d1a3]`

- `SEMP_CLOSURE` request with grace period (minimum 7 days).
- Finalization: revoke identity and encryption keys.
- Retention window after finalization.
- Local-part reassignment rules after retention expires.
- Sender-facing behavior: `policy_forbidden` with optional migration notice during retention.

### 3.4 `transparency/` Key Transparency

`[commit e9400bf]`

- Append-only Merkle tree log of key events (creation, rotation, revocation, successor, migration).
- Signed tree head (STH) with monotonic index.
- Inclusion proofs on key fetch.
- Consistency proofs across STH pairs.
- Equivocation detection via observation gossip.
- Monitor-role interface (out-of-band watcher).

### 3.5 `extensions/largeattachment/` Large Attachment

`[commit ca908d3]`

- `semp.dev/large-attachment` wire-level extension.
- Attachment stored out-of-band, referenced by URL plus HKDF-derived per-attachment key.
- `K_attachment = HKDF-Expand(K_enclosure, "semp-attachment:" || attachment_id, L)`.
- AEAD with `ciphertext_hash` bound as additional-data field.
- Streaming decryption hook.
- Library currently has inline-attachment hashing in `enclosure/`; this extension is additive.

---

## 4. Breaking changes within existing packages

### 4.1 Scoped device certificates refinement ([keys/devicecert.go])

Library's `devicecert.go` was written 2026-04-10, before the spec's `4c14bf5` and `2b8c336`. Upgrade to match the current normative form:

- Scope object is five-field uniform shape: `send`, `receive`, `blocklist`, `keys`, `devices`. Each carries a `rate_limits` array.
- `send` and `receive` use the **matcher** shape: `mode` in `{unrestricted, restricted, denylist, none}`, `allow` and `deny` arrays, `rate_limits`, and `receive` additionally has `delivery_stage` (positive integer).
- `blocklist`, `keys`, `devices` use the **resource** shape: `read`, `write`, `rate_limits`.
- 10,000 entry cap on combined `allow`+`deny` size. Violation rejects with `scope_invalid`.
- Certificate lifetime cap 365 days (`expires_at` bound).
- `delivery_stage` only valid on `receive` matcher.

### 4.2 Handshake challenge abstraction ([handshake/message.go], [handshake/client.go])

`[commit 97e7bb0]`. The spec generalized first-contact policy to an extensible `challenge_type`.

- Library currently rejects any `ChallengeType != ChallengeTypeProofOfWork` at `handshake/client.go:179`. Spec expects extensibility; future challenge types (`invite_token`, human verification, third-party identity proof) MAY be added by extensions.
- Treat unknown `challenge_type` as non-satisfiable per `KEY.md §3.2.2`, not as a hard protocol error.
- First-contact policy (`KEY.md §3.2`) announces `mode: challenge` with `challenge_type`. Recipient server issues the challenge; sender satisfies it.

### 4.3 Session resumption ([session/], [handshake/])

`[commit a50cf1c]`. New `resume` handshake step.

- `SEMP_HANDSHAKE` with `step: "resume"` and `resumption_ticket` field.
- Server issues `resumption_ticket` after a successful full handshake. Ticket max lifetime 7 days.
- Ticket carries encrypted `K_resumption` under server-held ticket-encryption key (rotated at least quarterly).
- Resumed-session keys derive from `K_resumption` mixed with fresh ephemeral DH; not from ephemeral DH alone.
- Failure cases surface `resumption_failed`; client falls back to full handshake.
- No 0-RTT application data.

### 4.4 Clock skew tolerance ([conformance boundary across handshake/, delivery/, envelope/])

`[commit 2b4762d]`. Normative tiered tolerance for every timestamp-bearing field.

- Future-dated timestamps: MUST reject if `T > now + 15 min`; SHOULD reject if `T > now + 5 min`.
- Expired fields: MUST reject when `now > T + 15 min`; SHOULD reject at `now > T`; MAY grace 5 min.
- Senders MUST NOT rely on grace windows.
- Applies to `postmark.expires`, challenge `expires`, session `expires_at`, block list sync `timestamp`, queue state, backup bundle `created_at`, migration `migrated_at`, forwarder attestations, delegated cert lifetimes.

**Integration status (post-commit 659185e).** The `clockskew` package landed with `Default()` / `Strict()` tolerances and `CheckFutureTimestamp` / `CheckExpiry` helpers. `delivery/pipeline.go` migrated to `clockskew.CheckExpiry(..., Strict())` for `postmark.expires`. Open work that this cluster does NOT yet cover:

- **Migrate other validation sites to clockskew.** Today the following still use ad-hoc `time.Until` / `time.After` checks rather than the package: `handshake/client.go` PoW `req.Expires` floor check (line 208), receipt-side checks on session `ExpiresAt` in `handshake/server.go` and `handshake/federation.go`, `session/expirylog.go`, and any future observation / block-list / migration timestamp validators. Each site should switch to `clockskew.CheckFutureTimestamp` (for "produced at T" fields) or `clockskew.CheckExpiry` (for "valid until T" fields) so the tolerance posture is uniform.

- **Enforce sender-side headroom in Compose.** Spec §9.3.1 (lines 1780–1783) requires senders to set `expires_at` values with at least 15 minutes of headroom beyond the worst-case expected delivery delay so that receivers applying zero grace continue to accept on-time records. `envelope.Compose` accepts any `Postmark.Expires` value the caller provides. A sender-side guard (`Postmark.Expires < now + 15min` rejects with a typed error) belongs alongside the other compose-time validation, but adding it forces every test fixture to set `Expires` from `time.Now()` rather than the fixed dates many fixtures use today, which is non-trivial test churn that deserves its own commit.

Track migration as its own follow-up cluster; sender-side headroom enforcement as a second.

### 4.5 Queuing, retry, and cancellation ([delivery/submission.go])

`[commit e864388, b0869f8]`

- `SEMP_SUBMISSION` with `step: "cancel"` request and `cancel_response`.
- Retry schedule compose rule: base interval × multiplier, clamp at 6h, symmetric jitter in `[1-j, 1+j]` with `j ≥ 0.1`. Jitter MUST NOT reduce realized interval below 50% of first base interval (30s floor). Recommended schedule `{1m, 5m, 15m, 1h, 4h, 4h×N}` is pre-jitter.
- First base interval of 60s MUST be enforced (no shorter initial delay).
- Non-recoverable reason codes MUST NOT retry. Unknown reason code defaults to non-recoverable.

### 4.6 Staged delivery ([delivery/])

`[commit fe95e40]`. Device-sync delivery-disposition for staged filter pipelines.

- Envelope held for disposition by lower-stage devices before higher-stage delivery.
- `delivery_stage` on scoped cert `receive` matcher.
- `SEMP_DISPOSITION` sync message per `DELIVERY.md §3.2`.
- Conservative aggregation: any `suppress` at a stage drops the envelope; otherwise `advance`.
- Fail-open on stage timeout.

### 4.7 Signed delivery receipts, evidence, user policy ([delivery/], [reputation/])

`[commit 9de2ebb, 619a334]`

- `SEMP_DELIVERY_RECEIPT` record, signed by recipient domain under `SEMP-DELIVERY-RECEIPT:` prefix.
- Receipt covers `envelope_hash`, `recipient_domain`, `accepted_at`.
- Sender server verifies receipt before treating acknowledgment as terminal `delivered`.
- Receipts propagate to sending client via delivery event; server drops after client ack.
- Retention per `DELIVERY.md §1.1.1.6` and `CONFORMANCE §4.13.1` (SHOULD drop after client ack; MUST NOT exceed `postmark.expires + 30 days`).
- Envelope `evidence` properties (pointer into reputation abuse report).
- `SEMP_USER_POLICY` message frame for policy sync (block list, first-contact mode, other rule kinds).

### 4.8 Multi-device: registration, revocation, directory ([keys/])

`[commit 8db34b4]`. Brand-new records on top of existing `devicecert.go`.

- `SEMP_DEVICE` registration message. Carries `device_id`, `device_public_key`, `role` (`full_access` or `delegated`), `certificate_id`, `authorization` block (authorizing-device signature under `SEMP-DEVICE-AUTHORIZE:`), and outer identity signature under `SEMP-DEVICE-REGISTER:`.
- Enrollment flow per `KEY.md §10.2`: QR + numeric-code fallback; new device generates key pair plus `enroll_nonce`; existing device signs registration and wraps identity private key under new device pubkey; local pairing channel carries the bundle.
- `SEMP_DEVICE_REVOCATION` with reasons `{key_compromise, lost, retired, superseded}`. Authority: any full-access device revokes any device; self-revoke allowed; delegated device self-revoke requires `devices.write` scope.
- **Mandatory identity-key rotation cascade on `reason: key_compromise`**: revocation + successor record + new identity/encryption keys + prior-identity revocation in a single atomic submission. Servers MUST reject a bare `key_compromise` revocation without the cascade.
- `SEMP_DEVICE_DIRECTORY` monotonically versioned, identity-signed under `SEMP-DEVICE-DIRECTORY:`. Lists every active device with pubkey, role, certificate binding.
- Directory publication at the key endpoint on every enrollment or revocation. Monotonic revision; consumers reject any device-scoped signature from a device not in the current directory.

### 4.9 Reputation gossip bucketing ([reputation/observation.go])

`[commit 2427adb]`. Observation metrics published as power-of-two buckets.

- Sequence: `0, 1, 2, 4, 8, 16, ..., 1048576`.
- Applies to `envelopes_received`, `envelopes_rejected`, `abuse_reports`, `unique_senders_observed`, `handshakes_completed`, `handshakes_rejected`.
- Apply at publication time, not collection. Raw counters stay exact internally.
- New helper `Bucketize(int64) int64`.
- Test updates: `observation_test.go`, `observation_sign_test.go`, `trust_gossip_test.go` have exact-count assertions that will break.

### 4.10 Trust transfer asymmetric carry-over ([reputation/])

`[commit f8a6b8d]`. Trust history transfers between domains are asymmetric with a cooldown.

- Carry-over is subject to a cooldown window; details in current `REPUTATION.md §7`.
- Asymmetric: positive carry-over subject to tighter rules than negative carry-over.

### 4.11 Configuration versioning and update notifications ([discovery/])

`[commit 9a7c9f3, 18914ef]`

- `SEMP_CONFIGURATION` is the sole registry of protocol endpoints.
- `revision` (monotonic integer) and `ttl_seconds` required on every configuration document.
- `SEMP_CONFIGURATION_UPDATE` notification, signed by domain key.
- Stale cache invalidation rules; capability-error driven refetch; grace-window on failed refetch.
- Consumers reject a configuration whose `revision` is lower than cached.

### 4.12 Address-harvesting hardening on partition lookup ([discovery/partition.go])

`[commit 7342f81]`

- `hash` and `alpha` strategies RECOMMENDED; `lookup` strategy requires authenticated requests per `DISCOVERY.md §2.4.4`.
- Response size/content invariance so that existence is not inferable from lookup.

### 4.13 Extension trust model ([extensions/])

`[commit 2f94e7d]`

- Signed extension definitions, per-layer validation, enforcement layers.
- Reference SDK validator model per `EXTENSIONS.md`.

### 4.14 Tor-isolated discovery and key fetch ([discovery/], [keys/])

`[commit b21ea41]`

- Skip DNS for recipient domains ending in `.onion`.
- Fetch well-known URI over Tor circuit only.
- Reject v2 onion addresses (16-char label); require v3 (56-char).
- No clearnet fallback when Tor egress unavailable; surface `server_unavailable`.
- Third-party key relays MAY be used for `.onion` recipients only if the relay itself routes via Tor.
- Speculative crawl schedule randomized for `.onion` to prevent correlation with send intent.

### 4.15 Sender-time obfuscation (OPTIONAL) ([envelope/compose.go] or [delivery/])

`[commit 3a9811d]`. Client-side only; OPTIONAL.

- Random delay `[0, D]` before first submission, default `D ≤ 60s`, operator-configurable.
- MUST NOT push submission past `postmark.expires`.
- Apply only to first submission, not retries.
- Skip for envelopes user flags time-sensitive.

---

## 5. Out of library scope

Client-side only. These land in `semp-reference-client`, not the library:

- SMTP upgrade-signal headers: `SEMP-Capability`, `SEMP-Identity`, `SEMP-Domain`, `SEMP-Address` on outbound SMTP. `[commit 164fd71]`
- MIME composition rules for `legacy_required` fallback. `[164fd71]`
- Thread continuity with `Message-ID ↔ brief.message_id` mapping and synthetic cross-origin identifiers. `[164fd71]`
- Mixed-recipient split at user confirmation. `[164fd71]`
- Inbound legacy upgrade detection with four-step verification. `[164fd71]`
- IMAP / POP3 / JMAP protocol-agnostic framing. `[3ad56c2]`

---

## 6. Documentation and metadata

- Bump spec-version comment in `doc.go` from `0.1.0` to `0.2.0-draft`. `[commit 86bb1ad]`
- Purge AMQP and Kafka references from any transport docs. `[commit 60af577]`
- Replace any placeholder extension names with the generic placeholder per `[c18d4aa]`.
- Inconsistencies cleanup pass across docs per `[ed32298]`.
- README: soften the "spec-complete reference implementation, zero stubs remain" claim while catch-up is in flight.

---

## 7. Suggested landing order

Items grouped into thematic clusters. One commit per cluster keeps the history readable and avoids rewriting the same file across many small commits. Landing order within a cluster is listed parenthetically.

| # | Cluster | Items | Why grouped |
|---|---|---|---|
| 0 | Prep | Add `SPEC-GAP.md`; fix stray `C` in `.gitignore` | Housekeeping before catch-up |
| 1 | Reason-code registry | 1.1 | Smallest surface. Blocks everything that references a code name. **(Done in this catch-up pass.)** |
| 2 | Domain-separation prefixes | Section 2 | Purely additive constants in one file. All new signed records reference them. |
| 3 | Handshake tightening | 1.5, 1.6, 1.9, 4.2 | All touch `handshake/`: PoW cap 28, federation collapse to single mode, compression removal, challenge-type abstraction. |
| 4 | Envelope size and fan-out obfuscation | 1.2, 1.3 | Both touch `envelope/compose.go` and `seal/`. Padding field plus recipient-count bucket dummies. |
| 5 | First-contact plus address canonicalization | 1.4, 1.7 | First-contact binds `(sender_domain, recipient_address, postmark_id)`, which requires the canonical address form. Do them together. |
| 6 | Sender identity signature plus forwarding provenance | 1.8 | Big enclosure-struct change; own commit. |
| 7 | Reputation | 4.9, 4.10 | Both in `reputation/`: bucketed gossip counts, asymmetric trust transfer with cooldown. |
| 8 | Clock-skew tolerance | 4.4 | Tiered timestamp validation applied across `envelope/`, `handshake/`, `delivery/`. Cross-cutting; own commit. |
| 9 | Session resumption | 4.3 | New `session/resumption.go` plus `handshake/` resume step. |
| 10 | Delivery | 4.5, 4.6, 4.7 | All in `delivery/`: cancellation, staged delivery, signed receipts plus evidence plus user-policy frame. |
| 11 | Discovery | 4.11, 4.12, 4.13, plus fix `TestForwarderFailsWithoutResolverOrEndpoint` | Configuration versioning + update notifications, partition hardening, extension trust model, plus the pre-existing forwarder test failure noted in the library today. |
| 12 | Scoped device certificate refinement | 4.1 | `keys/devicecert.go` reshape; prerequisite for Cluster 13. |
| 13 | Multi-device | 4.8 | New `SEMP_DEVICE`, `SEMP_DEVICE_REVOCATION`, `SEMP_DEVICE_DIRECTORY` records. Depends on Cluster 12. |
| 14 | Tor-isolated discovery | 4.14 | `.onion` skip-DNS flow in `discovery/` and `keys/`. |
| 15 | Send-time obfuscation | 4.15 | OPTIONAL delay at compose time. |
| 16 | `migration/` package | 3.2 | New package. |
| 17 | `closure/` package | 3.3 | New package. |
| 18 | `recovery/` package | 3.1 | New package. Depends on Cluster 13 (device directory) for manifest cross-reference. |
| 19 | `transparency/` package | 3.4 | New package. |
| 20 | `extensions/largeattachment/` package | 3.5 | New package. |
| 21 | Docs and metadata | Section 6 | Version-header bumps, AMQP/Kafka removal from docs, README softening. |

Clusters 1 through 6 are the wire-breaking backbone. Clusters 7 through 15 are the main substance. Clusters 16 through 21 are additive modules that can ship in any order.

Rationale for grouping:
- Clusters bundle edits that touch the same package or share a dependency, so the build-test cycle runs once per cluster rather than per item.
- Each cluster is a coherent unit that a future reader can understand without referencing adjacent commits.
- Where a cluster is large (Cluster 10 Delivery, Cluster 13 Multi-device), it may split into sub-commits if the diff grows unwieldy. The cluster remains the planning unit.

## 8. Pre-existing issues folded into catch-up

The library has two pre-existing conditions that are not spec-gap items but should be cleaned up in the course of catch-up:

- `TestForwarderFailsWithoutResolverOrEndpoint` in `test/discovery_forwarder_test.go` fails on `main` independent of any catch-up work. The assertion expects the reason string to mention "resolver" but the current implementation returns a generic "forwarding to remote domain failed". Fold the fix into Cluster 11 Discovery.
- `.gitignore` has a stray `C` character on its final line with no trailing newline. Fold the fix into Cluster 0 Prep or any subsequent commit that touches repo housekeeping.

---

## Cross-reference

- Spec repo: `semp-dev/semp-spec`. Baseline `3208899`, HEAD `3a9811d` at gap-list time. Running `git log 3208899..HEAD` in the spec repo enumerates every change.
- Specification style: RFC-normative language; no inline dashes per the project style memo.
- Protocol invariants to never break during catch-up: envelope canonicalization determinism, domain-separation on every Ed25519 signature, existence-oracle indistinguishability of rejections, server-distrust posture for enclosure plaintext.
