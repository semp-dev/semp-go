# semp-go Spec Gap

Consolidated catch-up list for bringing `semp-go` current with the SEMP specification at `semp-dev/semp-spec`.

## Status summary

The catch-up has effectively closed: every wire-breaking item, every new optional-module package, and every server-side state machine is implemented. What remains breaks into three categories.

**Genuinely open in the library:**

The Phase 1 JSON test-vectors runner ([`test/vectors_runner_test.go`]) surfaces four real drift items where semp-go's behavior disagrees with the published vectors. Each is currently `t.Skip`'d in the runner with a pointer back to this section so the suite stays green; landing the fix here flips the corresponding skip.

- ~~**VR-1** Canonical envelope strips empty `extensions` maps.~~ Landed. `envelope.Postmark.Extensions` and `seal.Seal.Extensions` no longer carry `omitempty`; both layers now emit `extensions:{}` verbatim per ENVELOPE.md §4.3.
- ~~**VR-2** Canonical envelope emits `first_contact_token: null`.~~ Landed. `seal.Seal.FirstContactToken` now carries `omitempty` and disappears from canonical bytes when nil.
- ~~**VR-3** Rekey HKDF info labels.~~ Landed. The `InfoRekey*` constants are now type-aliases of the corresponding `InfoSession*` constants per `VECTORS.md` §2.2; rekey relies on salt-based separation only.
- ~~**VR-4** Required-extension rejection scope.~~ Landed. `extensions.Validate` now rejects any required-but-unregistered extension regardless of namespace per `EXTENSIONS.md` §3.

All four Phase 1 vector-runner findings (VR-1 through VR-4) are closed. Categories that were `t.Skip`'d in `test/vectors_runner_test.go` are now exercised directly.

**Out of library scope (semp-reference-client):**

- §3.1 Restore-flow orchestration (combines records + bundle + Shamir + new-key generation)
- §3.1 Full client-side cascade driver (`recovery.VerifySuccessorTwoSignatures` + `keys.CompromiseRotation` primitives are in the library; the client driver that orchestrates them is not)
- §3.3 Cancellation by recovery-restored device per §3.2 (touches client-side restore)
- §4.8 Enrollment local-pairing bundle per §10.2.2 step 5
- All client-side legacy / MIME / upgrade-signal items per §5

**Spec-deferred (no library work today):**

- §3.2 §5.2 delegated forwarding mechanism — spec explicitly defers to a future revision; the active-client forward path is already covered by §6.6 in `enclosure/`
- §3.2 `forwarding_authorization` extension key + schema — spec extensions slot landed in `MigrationRecord.Extensions`; specific key + payload shape deferred
- §3.5 streaming AEAD per §3.3 — chunked AEAD modes deferred to a future extension

**Operator-supplied (not gaps in the library):**

- Durable persistence backends behind every Store / Registry / Counter interface — the library ships in-memory references for every one of them
- TLS certificates, monitoring, deployment infrastructure
- Operator policy values (retention windows, rate-limit tiers, allow / deny lists)

The `Open follow-ups` lists below within each section are kept as historical record. Items marked `~~struck through~~` have landed; remaining bullets are the items captured under the three categories above.

---

## How to read this document

Each item names the authoritative spec commit that introduced it and the library area it touches. Items are grouped by impact. Within each group the order is rough suggested implementation sequence. Wire-breaking items come first; additive extensions and new optional modules come later.

`[commit]` references the `semp-spec` commit. `[path]` references the `semp-go` file or package.

## Baseline (historical)

- **Library catch-up baseline:** `3c13837` (2026-04-13, "Security audit: sanitize error messages, fix session race").
- **Corresponding spec commit (approximate):** `3208899` (2026-04-13, "Add hybrid PQ wrapping, AAD binding, and signature domain separation").
- **Spec HEAD at the time the gap-list was started:** `3a9811d` (2026-04-23, "Specify OPTIONAL client-side send-time obfuscation").
- **Commits caught up:** all 41 of the original gap-list, plus subsequent spec changes through `4941913` (MIGRATION §3.1 extensions slot).

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

**Integration status.** Scaffolding landed in commit e511738: `enclosure.SignEnclosure`, `VerifyEnclosureSignature`, `SignForwarderAttestation`, `VerifyForwarderAttestation`, the `Signature` and `ForwardedFrom` types, and the canonical eliders.

Compose-side integration landed in a follow-up: `ComposeInput` gained `IdentityPrivateKey`, `IdentityKeyID`, and `SkipSenderSignature` fields, and `Compose` now invokes `SignEnclosure` before encryption (default-on, opt-out for tests and specialized flows). `TestEnvelopeRoundTrip` was extended to verify the decrypted enclosure carries a valid sender_signature.

Open work still pending:

- ~~The decrypt paths do not invoke `VerifyEnclosureSignature` after decryption.~~ Landed: `envelope.OpenAndVerify(ctx, env, suite, candidates, resolver)` decrypts the brief and enclosure for one of the candidate keys and runs the §6.5.3 sender-signature check via a `SenderKeyResolver` callback that maps (sender address, key_id) → public key bytes. Returns an `OpenAndVerifyResult` with `Brief`, `Enclosure`, plus per-step `SenderSignatureVerified` / `SenderSignatureError` / `ForwardingChainVerified` / `ForwardingChainError` outcomes so callers can render the §6.5.3 "MUST NOT silently render" warning rather than dropping the envelope. Existing `OpenEnclosure*` primitives unchanged; `OpenAndVerify` is the conformant entry point. `ErrSenderKeyUnknown` is the canonical resolver-side "no published key matches this (address, key_id)" sentinel.
- ~~No higher-level helper enforces `ENVELOPE.md §6.6.3`'s rule.~~ Landed: when `enc.ForwardedFrom != nil`, `OpenAndVerify` runs the §6.6.4 three-step flow (outer sender, forwarder attestation, original sender) and reports per-step results in the `ForwardingChainVerified` / `ForwardingChainError` fields. The §6.6.3 cross-check `forwarder_attestation.key_id == outer sender_signature.key_id` is enforced before the attestation signature is computed; mismatched key_ids fail before any cryptographic verification runs.

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

**Status:** Record types and signing primitives landed in new `recovery/` package:

- `SuccessorRecord` (SEMP_SUCCESSOR) with `PrepareSuccessorSignatures` + `SignSuccessorRecovery` / `SignSuccessorNewKey` / `SignSuccessorDomain` and a single `VerifySuccessorRecord`. All three signatures cover identical canonical bytes (with all three values elided) per §7.3; PrepareSuccessorSignatures populates Algorithm/KeyID on every block before any signing pass so the canonical input is stable.
- `RecoverySetManifest` (SEMP_RECOVERY_SET_MANIFEST) with `SignManifest` / `VerifyManifest` under SEMP-RECOVERY-MANIFEST:. Validate enforces threshold/total_shares consistency, contributor count, share_index uniqueness, and device_id uniqueness.
- `RecoveryShareRecord` (SEMP_RECOVERY_SHARE) with `SignShareRecord` / `VerifyShareRecord` under SEMP-RECOVERY-SHARE:.
- `CheckShareMatchesManifest` cross-checks bundle_id/share_index/device_id/threshold/total_shares per §5.3 step 2.

Tests cover: successor round-trip + tamper detection + wrong-recovery-pubkey rejection; manifest round-trip + duplicate-share_index/device_id rejection + threshold/total_shares mismatch rejection; share record round-trip; CheckShareMatchesManifest happy path + every mismatch axis.

**Server-assisted bundle (§2-4) landed** in `recovery/bundle.go` + `recovery/bundle_crypto.go`:

- `BackupBundle` (SEMP_BACKUP_BUNDLE) with KDF block, AEAD payload, RecoveryVerifyPK, and outer identity-key signature. `BundlePayload` carries the inner identity key + every encryption key (active, superseded, revoked) + accumulated delivery receipts per §2.3 / §2.3.1.
- `BundleKDF` exports the §2.5 minima (`MinKDFMemoryKB` 65536, `MinKDFIterations` 2, `MinKDFParallelism` 1, `MinKDFSaltBytes` 16) and recommended defaults (262144 / 3 / 4). `BundleKDF.Validate` rejects sub-minimum parameters at every axis including a non-`argon2id` algorithm or a non-base64 salt.
- `NormalizeRecoverySecret(form, raw)` implements the §3.2 normalization: NFKC + whitespace trim for passphrases (with `MinPassphraseBytes` = 12 floor), lowercase + single-ASCII-space join for BIP-39 recovery codes.
- `DeriveBundleKey(secretBytes, kdf)` runs Argon2id with the validated parameters and returns the 32-byte K_bundle.
- `DeriveRecoverySignKey(bundleKey)` HKDF-Expand's K_bundle under info `SEMP-RECOVERY-SIGN-KEY-v1` and returns the deterministic Ed25519 (recovery_sign_sk, recovery_verify_pk) pair per §3.3. The seed is consumed once and not stored.
- `EncryptBundlePayload` / `DecryptBundlePayload` use XChaCha20-Poly1305 (24-byte nonce, empty AAD) per §2.5; the caller supplies the nonce so the bundle's `payload_nonce` field is the same value used here.
- `SignBundle` / `VerifyBundle` apply the user's identity-key signature under `crypto.SigCtxRecoveryBundle` over the canonical bytes with `signature.value` elided, per §2.4 / ENVELOPE.md §4.3.

Tests cover: passphrase + recovery-code normalization (NFKC fold, sub-minimum rejection, all-whitespace rejection, unknown-form rejection); DeriveBundleKey determinism + salt-sensitivity; KDF.Validate at every floor; AEAD round-trip + tamper + wrong-key rejection; bad-nonce rejection; DeriveRecoverySignKey determinism; SignBundle/VerifyBundle round-trip + tamper detection + unsigned-bundle rejection; full backup→restore end-to-end flow (passphrase → K_bundle → encrypt + sign; passphrase → K_bundle → decrypt + verify; wrong passphrase → AEAD failure).

**Shamir GF(256) primitive landed** in `recovery/shamir.go`:

- `SplitSecret(secret, threshold, totalShares, randSrc)` returns N shares (1-byte index, len(secret)-byte value) such that any threshold of them reconstruct via Lagrange interpolation. Per-byte polynomial: constant term is the secret byte, higher coefficients are uniform random from `randSrc` (defaults to `crypto/rand.Reader`). Parameter floors enforce the §5.1 bounds (`MinShamirThreshold` 2, `MaxShamirTotalShares` 16, threshold ≤ totalShares).
- `CombineShares(shares)` reconstructs the secret by Lagrange-interpolating each byte position at x=0 over GF(256). Rejects empty input, zero-index shares, duplicate indices, and length-mismatched share values. Tolerates more-than-threshold shares (Lagrange is exact for any consistent point set).
- GF(256) arithmetic uses the AES reduction polynomial (`0x11b`) with generator `g = 3`, log/exp tables built once at `init()`. `gf256Mul`, `gf256Inv` are table-driven; `gf256MulRaw` (shift/XOR) seeds the tables.

Tests cover: every (M, N) pair within bounds with a 32-byte K_bundle-sized secret; arbitrary M-subsets reconstruct (not just the first M); fewer than M shares diverge; share indices are 1-based and unique; deterministic output under a fixed RNG; differing RNG seeds produce differing shares (independence); every parameter rejection path on Split (empty secret, M < 2, M > N, N > 16, zero parameters); every Combine rejection path (empty, zero index, duplicate index, mismatched length); 1-byte secret edge case; M = N = 16 maximum-parameter case; over-determined inputs (more than M shares) reconstruct; share order does not affect output.

**Bundle storage layer landed.** `recovery/bundle_store.go` adds a `BundleStore` interface (PutCurrent / GetCurrent / History / DeleteAll / PruneSuperseded) for §4 server-side bundle storage plus `NewInMemoryBundleStore()` reference implementation. PutCurrent enforces the §4.2 step 3 supersedes-pointer rule (uploaded bundle's `supersedes` MUST match prior current's `bundle_id`, or both empty for the first upload); mismatch returns `ErrSupersedesMismatch`. PruneSuperseded enforces the §4.4 30-day floor (`MinSupersededRetention`); sub-floor retention values are clamped up. History returns current first, then superseded newest-first. The store treats `encrypted_payload` as opaque — the server MUST NOT decrypt per §4.2. Sentinel errors (`ErrBundleNotFound`, `ErrSupersedesMismatch`) for `errors.Is` matching. `NewInMemoryBundleStoreWithClock(nowFn)` constructor lets tests inject a deterministic clock for retention pruning.

The HTTP transport layer (POST/GET/DELETE per §4.1) is operator integration; the library provides the storage primitive and the §4.2/§4.4 retention semantics.

**Open follow-ups:**

- Restore flow orchestration (§6): combines the records + bundle + Shamir + new-key generation. Lives in `client/`.
- HTTP transport layer for §4.1 endpoints (POST/GET/DELETE wiring + per-IP rate limiting + ?history=true query parameter): server-package integration over the storage layer above.
- ~~Cross-check contributor pubkey against the device directory at restore time.~~ Landed: `recovery.CrossCheckManifestContributors(manifest, directory)` walks every contributor and verifies `device_id` is listed in `directory` with a matching `device_public_key` per §5.2's "MUST cross-check each contributor against the directory revision active at issued_at" rule. Returns a typed `*ManifestCrossCheckError` carrying the offending contributor's `share_index`, `device_id`, and a `CrossCheckReason` (`missing_device` | `pubkey_mismatch` | `algorithm_mismatch`) so a restore client can surface per-contributor diagnostics. The function takes a small `DirectoryView` interface to avoid an import cycle with `keys`; `(*keys.DeviceDirectory).AsDirectoryView()` is the adapter callers use to plug in a real device directory.
- Identity-rotation cascade orchestration helpers landed under `recovery.VerifySuccessorTwoSignatures` for §10.5.5; full client-side cascade driver remains.

### 3.2 `migration/` Provider Migration

`[commit 3862795, b0869f8]`

- `SEMP_MIGRATION` record with four signatures (`old_identity_signature`, `new_identity_signature`, `new_domain_signature`, `old_domain_signature`).
- Sequential sign-and-embed pattern: each signature covers record plus all prior signatures.
- All four signatures use `SEMP-MIGRATION-RECORD:` prefix; differentiated by signing key.
- Validate `migrated_at ≥ old_identity_key.created` and within clock-skew tolerance.
- Forwarding window (old provider forwards to new for bounded time).
- Cooperative vs unilateral mode.
- Third-party verification per `MIGRATION.md §7.5`.

**Status:** Wire records and signing primitives landed in new `migration/` package:

- `MigrationRecord` (SEMP_MIGRATION) with the §3.2 field set, including `*time.Time` for `forwarding_window_until` (carries explicit null) and `*Signature` for `old_domain_signature` (omitted in unilateral mode).
- `Mode` enum {cooperative, unilateral} plus exported forwarding-window bounds (`MinForwardingWindow` 30d, `RecommendedForwardingWindow` 180d, `MaxForwardingWindow` 730d).
- `PrepareSignatures` populates Algorithm/KeyID on every slot before any signing pass so the chained-signature canonical bytes are reproducible. Cooperative mode allocates the 4th slot; unilateral mode leaves it nil.
- `SignOldIdentity` / `SignNewIdentity` / `SignNewDomain` / `SignOldDomain` are the four sequential passes. Each rejects out-of-order calls (e.g., SignNewIdentity before SignOldIdentity) and cross-checks the slot's KeyID against the passed fingerprint. SignOldDomain rejects unilateral mode.
- `VerifyMigrationRecord` walks the §3.3 order. The verifier reproduces each pass's signing-time canonical bytes by clearing later slots' values during the canonicalization for an earlier pass: pass N's input has prior slots at final values, pass N's value elided, and later slots at "" (per the §3.3 "Each signature binds the record fields and all prior signatures" rule, later slots had not been signed yet at the moment of pass N).
- `CheckMigratedAtBound(r, oldKeyCreated, now)` enforces "MUST be at or after old identity key's created" and "MUST NOT be in the future beyond clock-skew tolerance" via `clockskew.Default()`.

Tests cover: cooperative and unilateral round-trip; signing-order enforcement (each pass rejects out-of-order calls); SignOldDomain rejected in unilateral mode; chained-signature tamper detection (mutating an earlier signature's value invalidates later signatures that committed to it); forwarding-window bounds (below min, at min, recommended, at max, above max); CheckMigratedAtBound rejects backdated and future timestamps.

**Endpoint orchestration + lockout + post-window bounce + third-party policy hooks landed.**

`migration/orchestrate.go`:

- `BuildSubmission(SubmitInput)` implements §4.1 steps 3-7 on the new provider side. Produces a 3-sig record (old_identity + new_identity + new_domain) with the old_domain slot pre-allocated. Per §4.2's chained-signature rule, the old domain's KeyID MUST be populated up front so the canonical bytes are stable across the four signing passes — `SubmitInput.OldDomainKeyID` carries this; the new provider obtains it from the old provider's discovery configuration before submitting.
- `AcceptSubmission(ctx, AcceptInput)` implements §4.1 step 8 + §4.2 obligations on the old provider side. Verifies the three submitted signatures, runs the §3.4 `migrated_at` bound check via `CheckMigratedAtBound`, applies the operator's `ForwardingPolicy` for windows beyond the spec range, registers the §6.1 lockout reservation BEFORE countersigning so a duplicate concurrent submission for the same old address fails with `ErrLocalPartLockedOut`, then countersigns with the old domain key. Rejects unilateral records (the old provider is not a participant in unilateral migration). Returns the 4-sig record ready for publication.
- `ErrForwardingWindowRefused` sentinel for operator-supplied policy refusals.

`migration/lockout.go`:

- `LockoutRegistry` interface (`Reserve` / `IsLockedOut` / `Release` / `PruneExpired`) + `NewInMemoryLockoutRegistry()` reference impl.
- `Reserve` returns `ErrLocalPartLockedOut` on collision with an unexpired entry; expired entries are silently overwritten (the §6.2 "after the window the local-part MAY be reassigned" rule realized lazily).
- `IsLockedOut` returns the establishing migration record id and the until-timestamp so the operator's HTTP layer can surface them in the §6.1 rejection.
- `PruneExpired` for janitor sweeps.

`migration/migration_notice.go`:

- `MigrationNotice` is the §5.3 body field; `BuildMigrationNotice(record, urlPattern)` constructs it from a published migration record (substituting `<record_id>` placeholder in the URL pattern when present).
- `MigrationNoticeRejection` + `NewMigrationNoticeRejection` produce the §5.3 envelope-rejection wire shape (type=SEMP_ENVELOPE, step=rejected, reason_code=policy_forbidden, reason="Recipient has migrated.").

`migration/thirdparty.go`:

- `VerifyThirdParty(ThirdPartyVerifyInput)` implements §7.1 steps 2-5 verification. Cooperative records use the existing 4-sig `VerifyMigrationRecord`; unilateral records walk the three present signatures via the per-pass verifier (no old domain).
- `ThirdPartyPolicy` bundles the three §7 hooks (`UpdateKnownCorrespondents` §7.2, `CarryReputation` §7.3, `MigrateBlockListEntries` §7.4) as `ThirdPartyHook func(ctx, record) error`. `ApplyThirdPartyPolicy` runs each non-nil hook in spec order; nil hooks silently skipped; per-hook errors aggregated into `*ThirdPartyPolicyErrors.Steps` with no short-circuit (every hook still runs).

§5 forwarding integration: the spec defers the delegated server-side re-enveloping mechanism to "a future revision" (§5.2), and the client-initiated forward path is already covered by the §6.6 forwarding primitive in `enclosure/`. No new library code needed; operators wire `enclosure.SignForwarderAttestation` when forwarding via a still-active client. Spec-deferred portion explicitly out of scope.

The forwarding-authorization extension slot is now schema-aligned. Spec commit `4941913` added an `extensions` field to MIGRATION.md §3.1 / §3.2 and tightened the §5.2 wording so the speculative `forwarding_authorization` extension key is correctly attributed to a future revision. Library mirror lands `MigrationRecord.Extensions extensions.Map`; the existing `MarshalWithElision` canonical-bytes routine covers the new field uniformly across all four §3.3 signing passes, so any extension content is attested by all four signers (including the old domain's countersignature acknowledging a delegation it will later honor). Backwards compatibility: empty Extensions map omits the field on the wire (`omitempty`); records produced before the spec change serialize identically.

Tests cover: BuildSubmission cooperative + unilateral; window bounds rejection (zero / below min / above max); AcceptSubmission round-trip with full 4-sig VerifyMigrationRecord; AcceptSubmission rejects unilateral records; AcceptSubmission rejects bad old_identity_pub; ForwardingPolicy gate fires; duplicate-submission produces `ErrLocalPartLockedOut`; LockoutRegistry Reserve/Release/Prune lifecycle; MigrationNotice URL pattern substitution + default reason; VerifyThirdParty cooperative + unilateral; ApplyThirdPartyPolicy spec order, nil-skip, error aggregation. All under `-race`.

### 3.3 `closure/` Account Closure

`[commit 9a9d1a3]`

- `SEMP_CLOSURE` request with grace period (minimum 7 days).
- Finalization: revoke identity and encryption keys.
- Retention window after finalization.
- Local-part reassignment rules after retention expires.
- Sender-facing behavior: `policy_forbidden` with optional migration notice during retention.

**Status:** Wire records and signing primitives landed in new `closure/` package:

- `Record` (SEMP_ACCOUNT_CLOSURE) with `Step` enum {request, cancel}, GracePeriodSeconds, IssuedBy device id, signature.
- Grace-period bounds exported per §3.1: `MinGracePeriod` (7d), `MaxGracePeriod` (90d), `RecommendedGracePeriod` (30d). Validate enforces both bounds on request records; cancel records skip the bound check because the request being canceled already validated.
- `SignRecord` / `VerifyRecord` under `SEMP-ACCOUNT-CLOSURE:` (spec commit 78198a7 added the previously-missing prefix; library mirrors as `crypto.SigCtxAccountClosure`).
- `Record.FinalizationAt()` returns requested_at + grace_period.
- `Record.IsFinalizable(now)` reports whether `now` has reached the finalization timestamp; cancel records always return false.

Tests cover: request and cancel round-trips; grace-period bounds across seven points (well below, below by one day, at minimum, recommended, at maximum, above by one day, far above); cancel skips bound validation; structural validation rejects (missing user_id, requested_at, issued_by, unknown step); tamper detection on grace_period_seconds; FinalizationAt math; IsFinalizable before/at/after deadline plus cancel-never-finalizable.

**Server-side finalization driver landed.** `closure/driver.go` adds:

- `Driver` tracks pending closure requests and runs the §4.2 atomic effects when each reaches its `FinalizationAt` timestamp. `Submit(ctx, r)` records an accepted request (rejects step=cancel and duplicate users via `ErrAlreadyPending`). `Cancel(ctx, userID)` is idempotent (returns `(false, nil)` for unknown users per §3.2 cancellation norms). `Tick(ctx)` walks pending requests, finalizes any whose grace deadline has passed, removes them from the pending set, and aggregates per-step errors into `*FinalizationErrors`.
- `FinalizationEffects` bundles the nine §4.2 hooks (`RevokeIdentityKey`, `RevokeEncryptionKeys`, `RevokeDeviceCertificates`, `TerminateSessions`, `DrainOutboundQueue`, `DeleteRecoveryBundle`, `CancelInflightMigrations`, `RetainBlockList`, `CeaseServing`). Each hook is `FinalizationEffectFunc func(ctx, userID) error`. Nil hooks are silently skipped — operators that do not implement a particular step (for example, an installation without a recovery bundle store) leave that hook nil. The driver does NOT impose a particular implementation; library types can plug in (e.g., a closure over `recovery.BundleStore.DeleteAll` for §4.2.6) but the operator wires the rest.
- §4.1 strict ordering: `Tick` rejects finalizing before `FinalizationAt` ("MUST NOT occur before the timestamp under any policy"). Tested.
- Driver does NOT short-circuit on per-step errors — every non-nil hook runs even if an earlier one fails, and errors aggregate into `*FinalizationErrors.Steps`. The pending entry is removed after the run regardless: §4.2 finalization is irreversible once the grace deadline passes; operator retry / escalation policy applies via the returned error.
- Concurrency-safe via internal mutex; tested under `-race` with 50 concurrent submitters / cancelers / tickers.

Tests cover: submit tracks request; duplicate Submit rejected with `ErrAlreadyPending`; Submit rejects step=cancel; Tick before deadline is a no-op; Tick at deadline runs every non-nil hook in §4.2 spec order; nil hooks silently skipped; Cancel before deadline prevents finalization; Cancel-unknown is idempotent; effect errors aggregated into `*FinalizationErrors` with per-step keys and the pending entry still removed; multi-user Tick processes in deterministic user_id order; concurrent submit/cancel/tick.

**Open follow-ups:**

- Home-server closure_pending state: persistent record keyed by user_id with finalization timestamp, served to every authenticated client of the account so user-visible §3.3 behavior surfaces uniformly. (The Driver holds the pending set in memory; persistence is the operator's storage layer.)
- Ingress handling after finalization (§5): policy_forbidden / silent acknowledgment during retention window.
- Local-part reassignment policy hooks per §6.
- Cancellation by recovery-restored device per §3.2: certificate dated after requested_at must be accepted as a full-access cancel signer.

### 3.4 `transparency/` Key Transparency

`[commit e9400bf]`

- Append-only Merkle tree log of key events (creation, rotation, revocation, successor, migration).
- Signed tree head (STH) with monotonic index.
- Inclusion proofs on key fetch.
- Consistency proofs across STH pairs.
- Equivocation detection via observation gossip.
- Monitor-role interface (out-of-band watcher).

**Status:** Wire records, RFC 6962 hashing, and proof verification landed in new `transparency/` package:

- Record types: `LogEntry` (§2.2 with event enum {publish, rotate, revoke}, key_type enum {identity, encryption}, supersedes/revoked_at/revoked_reason fields per event), `SignedTreeHead` (§2.3), `InclusionProof` (§3.1), `ConsistencyProof` (§3.2).
- RFC 6962 primitives: `LeafPrefix`/`InteriorPrefix` byte constants (0x00, 0x01); `HashLeaf(bytes)` → SHA-256(0x00||bytes); `HashInterior(left, right)` → SHA-256(0x01||left||right); `HashLeafFromEntry(LogEntry)` marshals canonically and hashes.
- Proof verification: `VerifyInclusionProof(p, rootHash)` walks the leaf-index bit pattern per RFC 6962 §2.1.1; `VerifyConsistencyProof(p, firstRoot, secondRoot)` runs the §2.1.2 algorithm including the "first tree's root MAY be a complete subtree of the later tree" branch; both reject path-length mismatches, tampered leaf hashes, and tampered tree sizes.
- STH lifecycle: `SignSTH` / `VerifySTH` under SEMP-TRANSPARENCY-STH: (spec commit 3063cbf added the previously-missing prefix; library mirrors as `crypto.SigCtxTransparencySTH`). `CheckSTHFresh(s, now)` enforces the §2.3 1-hour freshness bound via `clockskew.CheckExpiry`.
- Validation: `LogEntry.Validate` + `SignedTreeHead.Validate` enforce required fields plus the §2.2 event-vs-supersedes / event-vs-revoked-fields cross-rules.

Tests cover: inclusion-proof round-trip across nine tree sizes (1, 2, 3, 5, 7, 8, 16, 17, 100, 257) with verification on every leaf; inclusion-proof tamper detection (leaf_hash, leaf_index); consistency-proof round-trip across seven (from, to) pairs including the boundary cases; consistency tamper detection (second root, from_size); equal-size consistency (path empty, equal roots); STH sign/verify round-trip + log_size tamper detection; CheckSTHFresh rejection of a 3-hour-old STH; LogEntry.Validate event/supersedes/revoked-at cross-rules; HashLeafFromEntry determinism.

**Open follow-ups:**

- Server-side log storage: append-only persistence for leaves, ordered by insertion; build the Merkle tree on top so STH and proof generation read from the same source of truth.
- §2.4 endpoint handlers (GET /sth, /inclusion, /consistency, /entries) plus discovery integration.
- §4.1 augmented SEMP_KEYS response: clients receiving keys from a transparency-enabled domain MUST receive a current STH and an inclusion proof for the most recent event of each returned key.
- §5 gossip via observations: the SEMP_TRUST_OBSERVATION extension that lets domains publish each other's STHs as a §7.2 split-world detection mechanism.
- §6 monitor behavior: an out-of-band watcher that fetches STHs, verifies consistency proofs across the timeline, and surfaces equivocation alarms.

### 3.5 `extensions/largeattachment/` Large Attachment

`[commit ca908d3]`

- `semp.dev/large-attachment` wire-level extension.
- Attachment stored out-of-band, referenced by URL plus HKDF-derived per-attachment key.
- `K_attachment = HKDF-Expand(K_enclosure, "semp-attachment:" || attachment_id, L)`.
- AEAD with `ciphertext_hash` bound as additional-data field.
- Streaming decryption hook.
- Library currently has inline-attachment hashing in `enclosure/`; this extension is additive.

**Status:** Wire records and crypto primitives landed in new `largeattachment/` package:

- `Item` struct mirrors the §2.2 schema (id, filename, mime_type, plaintext_size, url, ciphertext_hash, aead_algorithm, aead_nonce, extensions). `ExtensionData` is the inner `data` shape with the items array.
- `ExtensionKey` constant = "semp.dev/large-attachment". AEAD algorithm constants for both supported variants (chacha20-poly1305, xchacha20-poly1305).
- `DeriveAttachmentKey(kdf, kEnclosure, attachmentID, outputLen)` implements §3.1 HKDF-Expand with info = "semp-attachment:" || attachment_id, using K_enclosure directly as the PRK.
- `AdditionalData(item)` implements §3.2: canonical JSON of the item with ciphertext_hash, aead_nonce, and extensions zeroed, so AEAD verification rejects swaps of filename or mime_type but tolerates the metadata fields the spec excludes.
- `CiphertextHash(bytes)` produces the §2.3 "sha256:hex" form; `VerifyCiphertextHash(item, bytes)` is the §6 step 3c receive-side check (constant-time compare under the hood).
- `ValidateURL` enforces §4.1: HTTPS only, FQDN host (at least one dot) or IPv6 literal in brackets. Bare IPv4 literals rejected; bare hostnames without a dot rejected.
- `Item.Validate()` enforces all §2.3 required fields, the no-path-separator filename rule, non-negative plaintext_size, and runs ValidateURL.

Tests cover: HKDF determinism + per-attachment-id distinctness; full encrypt/decrypt round-trip with AEAD additional-data binding; metadata-binding behavior (filename and mime_type changes break AAD; ciphertext_hash, aead_nonce, extensions changes are intentionally excluded); ciphertext-hash mismatch detection; URL validation across nine cases (FQDN, IPv6 with and without port, plain HTTP, bare IPv4 with and without port, localhost, empty, non-URL); item.Validate rejects on every required-field axis.

**Storage backend abstraction landed.** `largeattachment/store.go` adds a `Store` interface (Put / Get / Stat / Delete) for ciphertext-blob persistence plus `NewInMemoryStore()` reference implementation. Implementations MUST treat ciphertext as opaque (the bytes are AEAD-encrypted under a per-attachment key the storage server cannot derive); the in-memory reference enforces put-once semantics, optional declared-size verification (`ErrCiphertextSizeMismatch`), and idempotent delete. Sentinel errors (`ErrAttachmentNotFound`, `ErrAttachmentExists`, `ErrCiphertextSizeMismatch`) let callers branch via `errors.Is`. The Store decouples wire-level metadata (Item) from the operator's chosen backend (S3, IPFS, local disk, custom CDN) so the same §3.2 round-trip applies regardless.

**Upload + download primitives + enclosure integration landed.** `largeattachment/upload.go`:

- `Encrypt(EncryptInput)` implements §5: generates ULID-shaped attachment_id (Crockford base32), derives K_attachment via HKDF-Expand under `K_enclosure`, picks a fresh nonce per the suite's AEAD, builds the partly-populated Item, computes AAD per §3.2, AEAD-seals the plaintext, computes `ciphertext_hash`, and returns the fully-populated `Item` + the ciphertext bytes the caller uploads to `Item.URL`.
- `Decrypt(suite, kEnclosure, item, ciphertext)` implements §6: derives K_attachment, verifies `ciphertext_hash` against the supplied bytes (ErrCiphertextHashMismatch on §7.2 integrity failure before any AEAD work), reconstructs AAD, AEAD-opens, returns plaintext.
- Per-suite AEAD selection per §3.2: baseline suite uses `chacha20-poly1305` (12-byte nonce); PQ suite uses `xchacha20-poly1305` (24-byte nonce, wrapped via `chacha20poly1305.NewX` since the library's `crypto.AEAD` interface defaults to ChaCha20-Poly1305 for both suites — the wider attachment AEAD is package-local).
- `EncryptInput` carries optional `ID` / `AEADNonce` / `Extensions` so tests can drive deterministic output; production callers leave them zero and the helpers generate fresh values.

`largeattachment/enclosure.go` adds `extensions.Map` read/write helpers:

- `ReadFromExtensions(m)` returns the items in the `semp.dev/large-attachment` entry, tolerating both the typed `ExtensionData` shape (sender side) and the wire-decoded generic-map shape (receiver side).
- `SetOnExtensions(m, items...)` and `AppendToExtensions(m, items...)` install / merge items; Append rejects duplicate ids.
- `RemoveFromExtensions(m)` deletes the entry; `FindByID(m, id)` lookup.
- All write paths run `Item.Validate()` before mutating so a malformed item never lands in the entry.

Tests: §5/§6 round-trip with both baseline + PQ suites; ID is 26-char Crockford base32; deterministic output under caller-supplied id/nonce; ciphertext-tamper rejected (hash check + AEAD-open paths); AAD-tamper (filename / mime_type) breaks AEAD authentication; wrong-K_enclosure fails open; non-HTTPS URL rejected up front; suite-vs-item algorithm mismatch caught before AEAD work; extension-map round-trip including JSON wire-decode shape; merge preserving existing items; duplicate-id rejection.

**Open follow-ups:**

- Streaming decryption support per §3.3 (algorithm-specific chunked AEAD modes). Spec explicitly defers this to extensions; not in the base spec scope, so the base library does not implement it. A future extension can supply chunked AEAD by registering a new `aead_algorithm` value.

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

**Status:** Type refactor landed. `DeviceCertificate` now has the spec-shape fields (`device_id`, `device_public_key`, `account`, `issued_by`, `issued_at`, `expires_at`). `Scope` exposes the five uniform fields. `ScopeMatcher` carries `mode`/`allow`/`deny`/`rate_limits` (+ optional `delivery_stage` on receive). `ScopeResource` carries `read`/`write`/`rate_limits`. `RateLimitTier` enforces per-spec bounds. `Validate()` enforces the §10.3.3 well-formedness rules and the §10.3.8 365-day lifetime cap. inboxd's send-scope enforcement updated to use `ScopeMatcher.AllowsRecipient`. Tests cover all matcher modes, all entry types, every validation failure path, and the lifetime cap.

**Scope-enforcement runtime landed.** All four §4.1 follow-ups close in this commit:

- ~~`delivery_stage` enforcement at receive-side delivery dispatch.~~ Landed: `delivery.PartitionStages(PartitionInput)` implements §3.2.1 — partitions the account's devices by stage, applying the §10.3.3.1 implicit full-access rule (`max(delegated_stages_with_mode_not_none) + 1`, falling back to stage 1 when no qualifying delegate exists). Devices excluded by their receive matcher (mode, allow/deny) are dropped from the partition; delegates with no current cert are skipped (the §10.3.7.3 revocation effect). Output is `[]StagedHeldStage` ready for `StagedRunner.Hold`. The §10.3.3.1 rule that ALL delegates with mode != none contribute to the max-stage tally — even those that rejected this envelope — is enforced; a denylist delegate at stage 5 still pushes full-access to stage 6 even when its allow/deny rejects the current envelope. `CertificateProvider` interface decouples the partitioner from any particular cert-store implementation. `StagedRunner.Reevaluate(envelopeID, newStages)` covers §3.2.6 (cert-update / revocation while held): re-attaches prior dispositions to the matching new stage; `ErrEnvelopeNotHeld` sentinel for unknown envelopes.
- ~~Resource-permission enforcement at the blocklist / key-management / device-management endpoints.~~ Landed: `keys.CheckResourceRead(scope, kind)` / `CheckResourceWrite(scope, kind)` for the three §10.3.3.2 resources (`ScopeResourceBlocklist`, `ScopeResourceKeys`, `ScopeResourceDevices`). Returns `*semp.Error` with `Code == ReasonScopeExceeded` on denial, naming the offending resource so operator logs surface "blocklist read denied" rather than just "scope_exceeded". Full-access devices have no certificate and are not subject to scope gating; callers short-circuit via the role check before calling.
- ~~Rate-limit tier enforcement against rolling counters.~~ Landed: `keys.RateLimitCounter` interface (`Allow(ctx, key, tiers, now) (bool, error)`) + `NewInMemoryRateLimitCounter()` reference impl. Tiers are evaluated independently — an operation must fit within EVERY tier per §10.3.3.3 conservative aggregation. `amount_allowed: 0` is an absolute prohibition. Denied operations are NOT recorded against the counters per §10.3.4 ("MUST NOT record the operation against the counters"); the test pins this so a denied burst cannot compound and starve a victim's quota. `keys.CheckRateLimit(ctx, counter, key, tiers, now)` is the public gate that returns `*semp.Error` with `Code == ReasonRateLimited` on denial; an empty tier list is unconditionally permitted.
- ~~Issuance flow validation (KEY.md §10.3.5 step 6).~~ Landed: `keys.ValidateIssuance(ctx, signer, info, cert, now)` runs every §10.3.5 step 6 check: (1) signature verifies against the issuer's registered device key; (2) issuer is a full-access device per §10.3.9 (delegated devices MUST NOT issue certs); (3) issuer is not revoked; (4) all required fields present (delegates to `Validate`); (5) allow/deny within the 10,000-entry cap (delegates to `Validate`); (6) `expires_at` within the §10.3.8 lifetime bound (delegates to `Validate`). Returns `*semp.Error` with `ReasonAuthFailed` for signature/lookup/revoked failures, `ReasonScopeExceeded` for the delegated-issuer rule, `ReasonScopeInvalid` for structural failures, and `ReasonCertificateExpired` when `now >= expires_at`. `IssuerInfo` interface decouples issuance validation from any particular directory implementation; `IssuerInfoFunc` adapter for inline factories.

Tests cover: stage partitioner happy path (no-delegate fallback, delegate-then-fullaccess implicit stage, multi-delegate same-stage grouping), every exclusion rule (matcher reject, mode=none, missing cert, enclosure_recipients filter), and the §10.3.3.1 max-stage tally subtlety (a delegate that rejected this envelope still counts toward the max). `StagedRunner.Reevaluate` round-trip + unknown-envelope sentinel. Resource gates: granted, denied (each kind), unknown kind. Rate limiter: tier enforcement, multi-tier conservative aggregation, amount_allowed=0 prohibition, empty-tier passthrough, denial-not-counted invariant. Issuance validation: happy path, delegated-issuer rejection, revoked-issuer rejection, unknown-issuer rejection, mismatched-signature rejection, expired-cert rejection, lookup-error propagation. All under `-race`.

### 4.2 Handshake challenge abstraction ([handshake/message.go], [handshake/client.go])

`[commit 97e7bb0]`. The spec generalized first-contact policy to an extensible `challenge_type`.

- Library currently rejects any `ChallengeType != ChallengeTypeProofOfWork` at `handshake/client.go:179`. Spec expects extensibility; future challenge types (`invite_token`, human verification, third-party identity proof) MAY be added by extensions.
- Treat unknown `challenge_type` as non-satisfiable per `KEY.md §3.2.2`, not as a hard protocol error.
- First-contact policy (`KEY.md §3.2`) announces `mode: challenge` with `challenge_type`. Recipient server issues the challenge; sender satisfies it.

### 4.3 Session resumption ([session/], [handshake/])

`[commit a50cf1c]`. New `resume` handshake step. **Landed.**

- `SEMP_HANDSHAKE` with `step: "resume"` and `resumption_ticket` field. Implemented as `handshake.Resume` and `handshake.StepResume`; the `Accepted` message gained optional `ServerNonce` / `ServerEphemeralKey` / `ResumptionTicket` fields (omitempty so full-handshake bytes are unchanged).
- Server issues `resumption_ticket` after a successful full handshake. Ticket max lifetime 7 days. Issued by `session.TicketIssuer`; `OnConfirm` populates the field automatically when a ticket issuer is configured on the server.
- Ticket carries encrypted `K_resumption` under server-held ticket-encryption key (rotated at least quarterly). Implemented as `session.StatelessTicketIssuer`: each ticket is `[ticket_id (16B) | aead_nonce (12B) | AEAD(JSON{identity, K_resumption, expires_at}, AAD=ticket_id)]`. Single-use via in-memory consumed-ticket cache keyed by `ticket_id`; `PruneConsumed` sweeps expired entries.
- Resumed-session keys derive from `K_resumption` mixed with fresh ephemeral DH; not from ephemeral DH alone. Implemented as `crypto.DeriveResumedSessionKeys` per HANDSHAKE.md §2.8.3.
- Failure cases surface `resumption_failed`; client falls back to full handshake. The library's `OnResume` returns typed errors that the driver/caller maps to `resumption_failed`; the spec's fallback logic is the caller's responsibility (try `Resume`, on error perform a full handshake).
- No 0-RTT application data. The `Resume` wire shape carries no envelope-bearing fields; the spec's "no 0-RTT" rule is enforced structurally.

**Open follow-ups:**

- ~~Federation resumption (HANDSHAKE.md §2.8.7)~~ Landed: `FederationResume` wire type, `FederationAccepted` resume-only fields, `Responder.OnResume`, `Initiator.Resume` / `Initiator.OnResumeAccepted`, `LoadResumptionSecret` setter, ResponderConfig.TicketIssuer field. `OnResume` cross-checks the ticket-bound identity against the request's `server_domain` so a ticket leaked for one domain cannot be replayed under another. End-to-end exercised by `TestFederationHandshakeResume`.
- ~~Driver helper for the §2.8.5 fallback.~~ Landed in `handshake/resume_driver.go`: `RunClientResume(ctx, stream, c, ticket)` and `RunInitiatorResume(...)` drive the resume exchange (Send Resume → Recv Accepted | Rejected). `RunClientResumeOrFull(...)` composes the two paths: tries Resume first, and on a §2.8.5 fallback signal calls caller-supplied factories (`freshStream`, `freshClient`) and runs `RunClient` against them. `IsResumptionFailed(err)` is the public predicate that recognizes the three §2.8.5 fallback codes (`resumption_failed`, `configuration_stale`, `no_session`); other codes (`policy_forbidden`, `version_unsupported`, `challenge_failed`, `blocked`) intentionally do NOT trigger fallback so a substantive policy decision is not silently masked. `RejectionCode(err)` is the generic accessor for callers that want to branch on a specific code beyond the fallback predicate.

### 4.4 Clock skew tolerance ([conformance boundary across handshake/, delivery/, envelope/])

`[commit 2b4762d]`. Normative tiered tolerance for every timestamp-bearing field.

- Future-dated timestamps: MUST reject if `T > now + 15 min`; SHOULD reject if `T > now + 5 min`.
- Expired fields: MUST reject when `now > T + 15 min`; SHOULD reject at `now > T`; MAY grace 5 min.
- Senders MUST NOT rely on grace windows.
- Applies to `postmark.expires`, challenge `expires`, session `expires_at`, block list sync `timestamp`, queue state, backup bundle `created_at`, migration `migrated_at`, forwarder attestations, delegated cert lifetimes.

**Integration status (post-commit 659185e).** The `clockskew` package landed with `Default()` / `Strict()` tolerances and `CheckFutureTimestamp` / `CheckExpiry` helpers. `delivery/pipeline.go` migrated to `clockskew.CheckExpiry(..., Strict())` for `postmark.expires`.

**Sweep across remaining peer-timestamp validators (commit `<this>`).** Two sites migrated to `clockskew.CheckExpiry(..., Default())`:

- `delivery/blocklist.go:119` — block-list entry expiry filter. Block entries are signed by the user on a device whose clock may differ from the home server's clock; the Default 15-minute grace keeps a freshly-expired block live during peer-clock disagreement so a sender does not slip through.
- `session/ticket.go:193` — stateless-ticket `Open` path. Tickets are issued by the server (possibly a peer server in a federation handshake) on its own clock; the Default grace lets a freshly-presented ticket survive up to 15 minutes of skew before the verifier rejects it as expired.

Both sites gained complementary grace-window tests asserting the new tolerance is applied (5 minutes past expiry → still live).

**Receiver-side session tolerance variants landed.** `session/session.go` adds tolerance-aware variants alongside the existing strict methods:

- `Session.ActiveWithGrace(now, grace)` — receiver-side variant of `Active`. Senders MUST use `Active` (strict, no grace) per CONFORMANCE.md §9.3.1; receivers MAY use `ActiveWithGrace(now, clockskew.Default().Grace)` to absorb up to 15 minutes of peer-clock skew before considering the session expired.
- `Session.CanRekeyWithGrace(now, grace)` — receiver-side variant of `CanRekey`.
- `Session.AcceptsIDWithGrace(sessionID, now, grace)` — receiver-side variant of `AcceptsID`. The grace applies only to the post-rekey transition-window's tail (PreviousIDExpiresAt), not to the current id which always matches.
- The strict variants now delegate to the WithGrace variants with `grace=0`, so behavior is unchanged for existing callers.

Tests cover: strict variants reject past-expiry; receiver variants accept within the grace window; receiver variants reject past the grace window; negative grace degrades to strict semantics.

**Sites audited and intentionally NOT migrated** (peer-clock skew does not apply):

- `session/session.go` `PreviousEnvMAC` — local transition-window memory pruning, not a peer-tolerance site.
- `session/ticket.go` consumed-ticket cache (`PruneConsumed`, `isConsumed`) — local memory pruning of the in-memory cache; not a peer-issued timestamp.
- `delivery/disposition.go:166` `IsStageComplete` — the deadline argument is locally computed (`startTime + timeout`); the staged-wait timer is a local-state machine, not a peer-tolerance site.
- `handshake/pow.go:106` solver-loop deadline — local solver timer.
- `delivery/inboxd/forwarder.go:612` — sleep duration; not a validation.
- `handshake/client.go:223` PoW `req.Expires` floor-vs-difficulty check — not an expiry validation, this checks whether the challenge has enough time-budget for its declared difficulty. The line below at 219 already uses `clockskew.CheckExpiry` for the actual expiry validity.

- ~~**Enforce sender-side headroom in Compose.**~~ Landed: `Compose` now rejects `Postmark.Expires` values closer than `MinSenderExpiryHeadroom` (15 minutes) per CONFORMANCE.md §9.3.1. Tests that intentionally compose already-expired envelopes (for pipeline-rejection tests) opt out via `ComposeInput.SkipExpiryHeadroomCheck = true`.

### 4.5 Queuing, retry, and cancellation ([delivery/submission.go])

`[commit e864388, b0869f8]`

- `SEMP_SUBMISSION` with `step: "cancel"` request and `cancel_response`.
- Retry schedule compose rule: base interval × multiplier, clamp at 6h, symmetric jitter in `[1-j, 1+j]` with `j ≥ 0.1`. Jitter MUST NOT reduce realized interval below 50% of first base interval (30s floor). Recommended schedule `{1m, 5m, 15m, 1h, 4h, 4h×N}` is pre-jitter.
- First base interval of 60s MUST be enforced (no shorter initial delay).
- Non-recoverable reason codes MUST NOT retry. Unknown reason code defaults to non-recoverable.

**Status:** Helpers landed in commit 6f60102. `RetryConfig` + `SanitizeRetry` + `BaseInterval` + `JitterInterval` + `NextAttempt` + `IsRecoverable` + `EffectiveDeadline` cover the §2.3-§2.4 rules. `QueueState` + `QueueRecordState` + `QueueState.SetTerminal` cover §2.5. `CancelRequest` / `CancelResponse` + `SubmissionStepCancel` / `SubmissionStepCancelResponse` cover §2.7.

**Server-side scheduler landed.** `delivery/scheduler.go` adds:

- `Scheduler` (§4.5 runtime). `Enqueue(envelope_id, recipient, postmark_expires)` inserts a fresh `queued` record with `next_attempt_at = now` and `Deadline = EffectiveDeadline(...)`. `Tick(ctx)` pulls every record whose `NextAttemptAt` has passed, runs the operator-supplied `DeliverFunc`, and reconciles the per-attempt outcome onto the record: delivered → terminal `delivered`, rejected with non-recoverable reason → terminal `rejected`, recoverable rejection / silent / transport failure → schedule retry via `NextAttempt`, deadline reached → terminal `expired`. The scheduler refuses to fabricate reason codes per §2.6 — only the actual returned reason is recorded.
- `Cancel(envelope_id, recipient)` and `CancelEnvelope(envelope_id)` for §2.7. Idempotent on already-terminal records (returns prior state with a §2.7.4 explanation).
- `PruneTerminal(retainFor)` evicts terminal records past the retention window. `MinTerminalRetention` (24h) is the §2.5 floor; sub-floor values are clamped up.
- `EventSink` callback fires once per terminal transition with a `SubmissionEvent` per §6.5 / CLIENT.md §6.5. Non-terminal attempts do NOT emit events.
- `Tick` is single-flighted: a concurrent caller gets `ErrTickInProgress` rather than running attempts twice for the same record.
- `Store` interface + `NewInMemoryStore()` reference implementation. Production deployments plug in a durable backend; the in-memory store satisfies the `StoreEnumerator` extension for whole-envelope cancellation.
- `QueueState.TerminalAt` (json:"-" so the wire shape stays clean) records the terminal-transition time for retention bookkeeping. `SetTerminal` now takes a `now time.Time` argument.

Tests cover: delivered happy path; non-recoverable rejection terminates without retry; recoverable rejection and silent both retry through to delivery; deadline-prior-to-retry transitions to expired; deadline-already-past skips Deliver and goes straight to expired; cancel transitions and is idempotent on already-terminal; cancel-unknown returns `ErrUnknownRecord`; whole-envelope cancellation across multiple recipients; PruneTerminal respects the 24h retention floor including sub-floor clamping; duplicate-Enqueue rejected; no event sink fire on non-terminal. Deterministic via injected `NowFn`; `-race` clean.

### 4.6 Staged delivery ([delivery/])

`[commit fe95e40]`. Device-sync delivery-disposition for staged filter pipelines.

- Envelope held for disposition by lower-stage devices before higher-stage delivery.
- `delivery_stage` on scoped cert `receive` matcher.
- `SEMP_DISPOSITION` sync message per `DELIVERY.md §3.2`.
- Conservative aggregation: any `suppress` at a stage drops the envelope; otherwise `advance`.
- Fail-open on stage timeout.

**Status:** Disposition types landed in commit c46398e. `Disposition` (the inner data of the `delivery-disposition` sync kind) plus `DispositionDecision` enum, `DispositionStageOutcome`, `AggregateDispositions` (suppress-wins per §3.2.3, fail-open per §3.2.4), `StagedHeld` / `StagedHeldStage` data structures, and `IsStageComplete` for the §3.2.2 wait-termination rule.

**Wait-and-aggregate runner landed.** `delivery/staged_runner.go` adds `StagedRunner` driving the §3.2 staged-delivery flow:

- `Hold(envelope_id, stages)` registers the stage partition (output of §3.2.1) and immediately invokes the operator's `StageDeliverFunc` for the lowest stage. Stages with no pending devices are pruned; non-monotonic stage lists are rejected. Duplicate envelope_ids return `ErrEnvelopeAlreadyHeld`.
- `IngestDisposition(envelope_id, submitter_device_id, d)` records a vote and enforces the §3.2.5 authentication rules: the submitter device_id (the device_id bound to the session that delivered the disposition) MUST match `d.DeviceID`; off-stage / later-stage / unknown-envelope dispositions are rejected. Repeat votes from the same device are silently dropped (the first vote stands; a device cannot retroactively flip suppress to advance).
- `Tick(ctx)` advances every held envelope whose current stage is complete per `IsStageComplete`. For each: if any stage-N device suppressed, invoke `StageSuppressFunc` and remove the envelope; otherwise advance to the next stage (invoking `StageDeliverFunc` for the next stage's pending set). When the final stage advances, invoke `StageCompleteFunc` and remove. The fail-open-on-timeout rule per §3.2.4 falls out of `IsStageComplete + AggregateDispositions(empty) == advance`.
- `Snapshot()` returns a deep-copy view; `HeldCount()` for monitoring.
- Concurrency-safe; all callbacks fire outside the runner's lock so a slow Deliver does not block IngestDisposition or other Tick passes.

Tests cover: Hold delivers stage 1 immediately; full-vote advance moves to stage 2 then completes; suppress wins over advance at the same stage and stage 2 is NOT delivered; fail-open on timeout advances; mismatched submitter / device_id rejected (§3.2.5 auth); off-stage device rejected (§3.2.5 stage membership); unknown-envelope ingest rejected; duplicate disposition is idempotent on the first vote; empty / non-monotonic / duplicate Hold rejected; Snapshot is a deep copy. Deterministic via injected `NowFn`; `-race` clean.

### 4.7 Signed delivery receipts, evidence, user policy ([delivery/], [reputation/])

`[commit 9de2ebb, 619a334]`

- `SEMP_DELIVERY_RECEIPT` record, signed by recipient domain under `SEMP-DELIVERY-RECEIPT:` prefix.
- Receipt covers `envelope_hash`, `recipient_domain`, `accepted_at`.
- Sender server verifies receipt before treating acknowledgment as terminal `delivered`.
- Receipts propagate to sending client via delivery event; server drops after client ack.
- Retention per `DELIVERY.md §1.1.1.6` and `CONFORMANCE §4.13.1` (SHOULD drop after client ack; MUST NOT exceed `postmark.expires + 30 days`).
- Envelope `evidence` properties (pointer into reputation abuse report).
- `SEMP_USER_POLICY` message frame for policy sync (block list, first-contact mode, other rule kinds).

**Status:** Wire records landed. `DeliveryReceipt` + `ComputeEnvelopeHash` + `SignDeliveryReceipt` + `VerifyDeliveryReceipt` + `VerifyEnvelopeBinding` cover §1.1.1. `UserPolicyMessage` + `PolicyOperation` + `PolicyOp` enum + `SignUserPolicyMessage` + `VerifyUserPolicyMessage` cover §7.1, including the §7.3 singleton-vs-list op rules (first_contact accepts only modify; remove requires entry_id; add requires entry). Spec commit 4e7eef7 registered the missing `SEMP-USER-POLICY:` domain-separation prefix; library mirrors it as `crypto.SigCtxUserPolicy`.

**Open follow-ups:**

- ~~Sender-server `delivered` flow: verify the receipt before acknowledging.~~ Landed: `inboxd.handleClientSubmission` now calls `verifyDeliveredReceipt` for every peer result; missing or malformed receipts are demoted to `StatusRejected` with `ReasonServerUnavailable` so the §2.3 retry path picks up the failure. Receipt is verified against the post-rebind `forwardEnv` (the bytes the recipient actually saw) rather than the pre-forward `env`.
- ~~Recipient-server inline issuance: produce a receipt alongside every `delivered` acknowledgment.~~ Landed: `inboxd.handleFederationSubmission` now calls `issueDeliveryReceipt` for every delivered outcome and attaches the result to the SubmissionResult. Receipt issuance failure demotes the result to `StatusSilent` rather than emitting an unverifiable acknowledgment. `SubmissionResult.Receipt` field added to the wire schema.
- ~~Receipt-retention pruning.~~ Landed: `delivery.ReceiptStore` interface + `NewInMemoryReceiptStore()` reference implementation. `Put(envelope_id, recipient, receipt, storedAt)` stores a freshly-issued receipt; `Acknowledge(envelope_id, recipient)` drops it after a client device has consumed the corresponding delivery event per §1.1.1.6 "MAY drop after acknowledgment"; `PruneUnacknowledged(cutoff)` evicts receipts past the configured push-notification retention window. The reference store drops on Acknowledge so no plaintext archive accumulates per the §2.5 correspondent-graph privacy posture. `DefaultReceiptRetention = 72h` matches the §2.4 server_max_retry_horizon default.
- ~~`evidence` envelope properties.~~ Resolved via spec audit: ENVELOPE.md does not define an envelope-level `evidence` property. The spec's "evidence" references are (a) the receipt itself acting as evidence per §1.1.1 (already implemented); (b) abuse-report `evidence` in REPUTATION.md §3.5 (will be implementable when REPUTATION integration lands); (c) the `forwarded_from` evidence block in §6.6 (already covered by the §6.6.4 forwarding-chain verification landed in `enclosure/`). No standalone library work required.
- ~~Home-server policy-version state.~~ Landed: `delivery.PolicyState` is the per-user authoritative policy view. `Apply(m *UserPolicyMessage)` enforces every §7.2 rule: monotonic `policy_version`, equal-version-later-timestamp tie-break, atomic apply of every operation (a single unsupported kind rejects the whole message; the state is not mutated until every op pre-flights). Returns a `*semp.Error` whose `Code` is `policy_kind_unsupported`, `policy_op_invalid`, or `policy_version_stale` per ERRORS.md §5; the wrapped `*PolicyApplyError` carries the offending kind, op index, and version pair. Supported kinds default to the §7.3 v1.0.0 set (`semp.dev/block`, `semp.dev/accepted_sender`, `semp.dev/first_contact`); `NewPolicyState(userID, kinds...)` lets operators register extension-defined kinds. List-shaped kinds (block, accepted_sender) treat `add` and `modify` as upsert (CRDT-style convergent semantics on the server; the verb distinction is preserved on the wire); `remove` is idempotent on a missing id (the version-monotonicity guard already catches replay at the message level). Singleton kinds (first_contact) accept only `modify`. `Snapshot()` returns a deep-copy view for propagation to other devices on next connection. Concurrency-safe via internal mutex; tested with concurrent `Apply` calls under `-race`.

  Reason-code constants registered in `semp/reasoncodes.go`: `ReasonPolicyKindUnsupported`, `ReasonPolicyOpInvalid`, `ReasonPolicyVersionStale`. Only `ReasonPolicyVersionStale` is recoverable per §5.

  Encrypted-at-rest persistence (§7.5) is the operator's persistence layer; `PolicyState` holds in-memory state only.

### 4.8 Multi-device: registration, revocation, directory ([keys/])

`[commit 8db34b4]`. Brand-new records on top of existing `devicecert.go`.

- `SEMP_DEVICE` registration message. Carries `device_id`, `device_public_key`, `role` (`full_access` or `delegated`), `certificate_id`, `authorization` block (authorizing-device signature under `SEMP-DEVICE-AUTHORIZE:`), and outer identity signature under `SEMP-DEVICE-REGISTER:`.
- Enrollment flow per `KEY.md §10.2`: QR + numeric-code fallback; new device generates key pair plus `enroll_nonce`; existing device signs registration and wraps identity private key under new device pubkey; local pairing channel carries the bundle.
- `SEMP_DEVICE_REVOCATION` with reasons `{key_compromise, lost, retired, superseded}`. Authority: any full-access device revokes any device; self-revoke allowed; delegated device self-revoke requires `devices.write` scope.
- **Mandatory identity-key rotation cascade on `reason: key_compromise`**: revocation + successor record + new identity/encryption keys + prior-identity revocation in a single atomic submission. Servers MUST reject a bare `key_compromise` revocation without the cascade.
- `SEMP_DEVICE_DIRECTORY` monotonically versioned, identity-signed under `SEMP-DEVICE-DIRECTORY:`. Lists every active device with pubkey, role, certificate binding.
- Directory publication at the key endpoint on every enrollment or revocation. Monotonic revision; consumers reject any device-scoped signature from a device not in the current directory.

**Status:** Record types and signing primitives landed in `keys/device.go` and `keys/device_sign.go`:

- `DeviceRegistration` (SEMP_DEVICE) with `DeviceAuthorization` inner block. `SignDeviceAuthorization` produces the authorizing-device signature under `SEMP-DEVICE-AUTHORIZE:` over `device_id || 0x00 || device_public_key || 0x00 || enrolled_at || 0x00 || enroll_nonce` (NUL-separated to close boundary-shift collisions). `SignDeviceRegistration` produces the outer identity signature under `SEMP-DEVICE-REGISTER:`. Validate enforces role/certificate_id consistency, supported authorization methods, and required scalar fields.
- `DeviceRevocation` with `Reason` enum and `RequiresIdentityRotation()` helper that callers use to drive the §10.5.5 cascade. `SignDeviceRevocation` / `VerifyDeviceRevocation` under `SEMP-DEVICE-REVOCATION:`. Validate enforces the reason / replacement_device_id consistency rule.
- `DeviceDirectory` with sorted-by-device_id canonicalization so signature output is independent of caller-supplied array order. `SignDeviceDirectory` / `VerifyDeviceDirectory` under `SEMP-DEVICE-DIRECTORY:`. Validate enforces device_id uniqueness, role/certificate_id consistency, and Revision >= 1. The rollback-detect rule (Revision >= cached) is the caller's responsibility because the cached value lives outside the record.
- `CheckEnrolledAtFresh(enrolled_at, now)` helper applies CONFORMANCE.md §9.3.1 default tolerance to the §10.2.3 15-minute submission-skew bound.

Tests exercise: outer + inner round-trip; outer-field tamper detection; inner authorization stale-nonce rejection and tampered-DeviceID rejection; full_access-with-CertificateID and delegated-without-CertificateID rejections; revocation round-trip; superseded-without-replacement and key_compromise-with-replacement rejections; RequiresIdentityRotation truth table; directory round-trip including reorder-invariance; duplicate-device_id rejection; revision=0 rejection.

**Open follow-ups:**

- ~~Identity-key rotation cascade orchestration on `reason: key_compromise`.~~ Landed in commit (this one): `keys.CompromiseRotation` bundle + `keys.BuildCompromiseRotation(input)` constructor + `keys.VerifyCompromiseRotation(ctx, suite, bundle, priorIdentityPub, recoveryVerifyPub)`. The bundle carries the four KEY.md §10.5.5 artifacts: device revocation (reason key_compromise, signed by prior identity key), successor record (recovery + new_key sigs populated; domain pending), new identity + encryption public keys, and a prior-identity revocation publication signed by the prior identity key. The verifier runs the device-side checks (every signature plus the cross-check that `prior_identity_revocation.replacement_key_id == new_identity_key_id`); the home server adds its `domain_signature` on receipt and runs the full three-sig successor verifier afterward. `recovery.VerifySuccessorTwoSignatures` was added alongside to support this two-of-three verification mode.
- ~~Home-server publication state.~~ Landed: `keys.DirectoryState` is the per-user mutable state (sorted device map, monotonic revision, current signed `DeviceDirectory`). `AddDevice` and `RevokeDevice` mutate the device set and emit a fresh signed directory each time; revoking an unknown device is a no-op (no revision bump). `keys.DirectoryStore` wraps multiple per-user states for a multi-account home server. State is concurrency-safe; revision rollback on signing failure preserves monotonicity.
- ~~Consumer rollback-detect cache.~~ Landed: `keys.DirectoryCache` is the per-(user_id) highest-accepted-revision tracker. `VerifyAndCache(suite, dir, identityPub, certCheck)` runs every §10.6.3 consumer rule (Validate, signature, monotonic revision check, optional `CertificateCheck` callback for delegated entries), and on success advances the cache. Returns a typed error on rollback so the caller can surface a §10.6.2 equivocation alarm. Reset is exposed for operator-driven manual overrides.
- Enrollment local-pairing bundle (§10.2.2 step 5): wrapping identity + encryption private keys under K_device_new for transfer to NEW. Belongs in `client/` (semp-reference-client) rather than the library.

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
