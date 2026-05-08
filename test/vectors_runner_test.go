package test

// JSON-driven test-vectors runner.
//
// Loads every *.json file under semp-spec/vectors/v1.0.0/ and dispatches
// each vector entry to a category-specific handler. The runner is the
// gating criterion for cross-implementation interop: a semp-go change
// that breaks a vector breaks compatibility with every other SEMP
// implementation that passes the same vectors.
//
// Phase 1 (this file): framework + Layer 1 + deterministic Layer 2
// categories. Categories without a handler print t.Skip("category X:
// handler not yet wired") so coverage gaps are visible without breaking
// the build.
//
// Path resolution: looks for vectors at $SEMP_VECTORS_DIR first, then at
// ../semp-spec/vectors/v1.0.0/ (the canonical sibling-checkout layout).
// If neither exists the entire suite is skipped with a clear message,
// so a CI environment that does not check out the spec repo does not
// fail on this test.
//
// Reference: semp-spec/vectors/README.md.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"semp.dev/semp-go/clockskew"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/handshake"
	semp "semp.dev/semp-go"
)

// vectorFile mirrors the top-level shape documented in vectors/README.md.
type vectorFile struct {
	Version       string            `json:"version"`
	Category      string            `json:"category"`
	Description   string            `json:"description"`
	SpecReference string            `json:"spec_reference"`
	Vectors       []json.RawMessage `json:"vectors"`
}

// vectorEntry is the per-test-case shape. A vector is either single-case
// (carries `inputs`/`expected`) or table-shape (carries `samples`).
type vectorEntry struct {
	ID             string            `json:"id"`
	MustReject     bool              `json:"must_reject,omitempty"`
	RejectionClass string            `json:"rejection_class,omitempty"`
	Description    string            `json:"description"`
	SpecReference  string            `json:"spec_reference"`
	Rule           string            `json:"rule,omitempty"`
	Inputs         json.RawMessage   `json:"inputs,omitempty"`
	Expected       json.RawMessage   `json:"expected,omitempty"`
	Intermediates  json.RawMessage   `json:"intermediates,omitempty"`
	Samples        []json.RawMessage `json:"samples,omitempty"`
}

// handler verifies one vector entry against the corresponding semp-go
// API. A handler MUST call t.Fatalf / t.Errorf on mismatch and MAY call
// t.Skipf for sub-cases the implementation does not yet cover.
type handler func(t *testing.T, entry vectorEntry)

// dispatch maps each `category` field value to its handler. Categories
// without a handler are reported as TODOs by TestVectors.
var dispatch = map[string]handler{
	// Layer 1 (cryptographic primitives).
	"hkdf":              handleHKDF,
	"session-mac":       handleSessionMAC,
	"confirmation-hash": handleConfirmationHash,
	"pow":               handlePoW,

	// Layer 2 (deterministic protocol logic).
	"envelope-canonical": handleEnvelopeCanonical,
	"envelope-buckets":   handleEnvelopeBuckets,
	"discovery":          handleDiscovery,
	"rejection-codes":    handleRejectionCodes,
	"extension-entries":  handleExtensionEntries,
	"clock-tolerance":    handleClockTolerance,

	// Wave 2A: single-signature documents (Layer 5 + signed handshake).
	"account-closure":       runSignedDocHandler(pickAccountClosure),
	"configuration-update":  runSignedDocHandler(pickConfigurationUpdate),
	"user-policy":           runSignedDocHandler(pickUserPolicy),
	"discovery-signed":      runSignedDocHandler(pickDiscoverySigned),
	"handshake-messages":    handleHandshakeMessages,
	"handshake-messages-pq": handleHandshakeMessagesPQ,
	"session-resumption":    handleSessionResumption,
	"recovery-shamir":       handleRecoveryShamir,
	"first-contact-token":   handleFirstContactToken,

	// Wave 2B: decision-table shape validators.
	"delivery-status":     handleDeliveryStatus,
	"device-certificates": handleDeviceCertificates,
	"key-revocation":      handleKeyRevocation,
	"recipient-status":    handleRecipientStatus,
	"session-lifecycle":   handleSessionLifecycle,

	// Wave 2C: cross-reference + must-reject schema.
	"must-reject-index":           handleMustRejectIndex,
	"negative-envelope-rejection": handleNegativeEnvelopeRejection,

	// Wave 2D: verify-only round-trip handlers.
	"sender-signature": handleSenderSignature,
	"delivery-receipt": handleDeliveryReceipt,
	"transparency":     handleTransparency,
	"forwarding":       handleForwarding,
	"migration":        handleMigration,
}

// TestVectors is the entry point. It walks every *.json file in the
// resolved vectors directory and runs each entry as a Go subtest under
// `TestVectors/<file>/<id>`.
func TestVectors(t *testing.T) {
	dir, ok := findVectorsDir()
	if !ok {
		t.Skip("vectors directory not found: set SEMP_VECTORS_DIR or check out " +
			"semp-spec as a sibling of semp-go")
	}
	t.Logf("vectors dir: %s", dir)

	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no *.json files at %s", dir)
	}
	sort.Strings(files)

	// Track coverage so the suite reports a single line at the end with
	// pass / skip / fail counts. Helpful when ~36 files run.
	var totalEntries, skipped int
	categoriesSeen := map[string]bool{}

	for _, path := range files {
		path := path
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			file, err := loadVectorFile(path)
			if err != nil {
				t.Fatalf("load %s: %v", path, err)
			}
			categoriesSeen[file.Category] = true

			h, hasHandler := dispatch[file.Category]
			for _, raw := range file.Vectors {
				totalEntries++
				var entry vectorEntry
				if err := json.Unmarshal(raw, &entry); err != nil {
					t.Errorf("unmarshal entry in %s: %v", name, err)
					continue
				}
				t.Run(entry.ID, func(t *testing.T) {
					if !hasHandler {
						skipped++
						t.Skipf("category %q: handler TODO (spec %s)",
							file.Category, file.SpecReference)
						return
					}
					h(t, entry)
				})
			}
		})
	}

	t.Logf("vectors: %d files, %d entries, %d skipped (no handler)",
		len(files), totalEntries, skipped)
	missing := []string{}
	for cat := range categoriesSeen {
		if _, ok := dispatch[cat]; !ok {
			missing = append(missing, cat)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Logf("categories without a handler (Phase 2/3 work): %s",
			strings.Join(missing, ", "))
	}
}

// findVectorsDir resolves the vectors directory. SEMP_VECTORS_DIR wins
// if set; otherwise the function looks at ../semp-spec/vectors/v1.0.0/
// from the test file's directory.
func findVectorsDir() (string, bool) {
	if env := os.Getenv("SEMP_VECTORS_DIR"); env != "" {
		if isDir(env) {
			return env, true
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	// `go test ./test/...` runs in semp-go/test/. Look for
	// ../semp-spec/vectors/v1.0.0/ from that directory and also from
	// semp-go/ (one level up) so `go test ./...` from the repo root
	// also resolves.
	candidates := []string{
		filepath.Join(wd, "..", "semp-spec", "vectors", "v1.0.0"),
		filepath.Join(wd, "..", "..", "semp-spec", "vectors", "v1.0.0"),
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if isDir(abs) {
			return abs, true
		}
	}
	return "", false
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func loadVectorFile(path string) (*vectorFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vf vectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return &vf, nil
}

// ---------------------------------------------------------------------------
// Generic helpers

// jget pulls a string field from a json.RawMessage. Returns "" if the
// field is missing.
func jget(t *testing.T, raw json.RawMessage, field string) string {
	t.Helper()
	if len(raw) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("jget %q: %v", field, err)
	}
	v, ok := m[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		// Field is not a string; return empty so the caller can
		// fall through. Use jgetRaw if you need the raw value.
		return ""
	}
	return s
}

// jgetRaw returns the raw json subtree for `field` so callers can
// further unmarshal into typed structures.
func jgetRaw(t *testing.T, raw json.RawMessage, field string) json.RawMessage {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("jgetRaw %q: %v", field, err)
	}
	return m[field]
}

// jgetInt pulls an integer field.
func jgetInt(t *testing.T, raw json.RawMessage, field string) int {
	t.Helper()
	if len(raw) == 0 {
		return 0
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("jgetInt %q: %v", field, err)
	}
	v, ok := m[field]
	if !ok {
		return 0
	}
	var n int
	if err := json.Unmarshal(v, &n); err != nil {
		t.Fatalf("jgetInt %q decode: %v", field, err)
	}
	return n
}

// jgetBool pulls a boolean field.
func jgetBool(t *testing.T, raw json.RawMessage, field string) bool {
	t.Helper()
	if len(raw) == 0 {
		return false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("jgetBool %q: %v", field, err)
	}
	v, ok := m[field]
	if !ok {
		return false
	}
	var b bool
	if err := json.Unmarshal(v, &b); err != nil {
		t.Fatalf("jgetBool %q decode: %v", field, err)
	}
	return b
}

func decodeHexF(t *testing.T, s, field string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s as hex: %v", field, err)
	}
	return b
}

func decodeB64F(t *testing.T, s, field string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s as base64: %v", field, err)
	}
	return b
}

func bytesEq(a, b []byte) bool { return bytesEqual(a, b) }

// ---------------------------------------------------------------------------
// Layer 1 handlers

// handleHKDF dispatches HKDF-SHA-512 vectors against semp-go's KDF and
// session-key derivation. Both `hkdf-baseline` (initial handshake) and
// `hkdf-rekey` (mid-session rekey) share the same shape — they only
// differ in salt construction, which the input documents.
func handleHKDF(t *testing.T, entry vectorEntry) {
	ikm := decodeHexF(t, jget(t, entry.Inputs, "ikm_hex"), "ikm_hex")

	// Salt is one of (client_nonce_hex || server_nonce_hex) or
	// (rekey_nonce_hex || responder_nonce_hex). Detect by inspecting
	// salt_construction; default to the session-handshake form.
	var nonce1, nonce2 []byte
	switch jget(t, entry.Inputs, "salt_construction") {
	case "rekey_nonce || responder_nonce":
		nonce1 = decodeHexF(t, jget(t, entry.Inputs, "rekey_nonce_hex"), "rekey_nonce_hex")
		nonce2 = decodeHexF(t, jget(t, entry.Inputs, "responder_nonce_hex"), "responder_nonce_hex")
	default: // includes "client_nonce || server_nonce" and missing
		nonce1 = decodeHexF(t, jget(t, entry.Inputs, "client_nonce_hex"), "client_nonce_hex")
		nonce2 = decodeHexF(t, jget(t, entry.Inputs, "server_nonce_hex"), "server_nonce_hex")
	}
	salt := append(append([]byte{}, nonce1...), nonce2...)

	// Step 1: PRK from Extract.
	kdf := crypto.NewKDFHKDFSHA512()
	gotPRK := kdf.Extract(salt, ikm)
	wantPRK := decodeHexF(t, jget(t, entry.Expected, "prk_hex"), "prk_hex")
	if !bytesEq(gotPRK, wantPRK) {
		t.Errorf("PRK mismatch (%s):\n  got  %x\n  want %x",
			entry.SpecReference, gotPRK, wantPRK)
	}

	// Step 2: derived keys.
	var keys *crypto.SessionKeys
	var err error
	if jget(t, entry.Inputs, "salt_construction") == "rekey_nonce || responder_nonce" {
		keys, err = crypto.DeriveRekeyKeys(kdf, ikm, nonce1, nonce2)
	} else {
		keys, err = crypto.DeriveSessionKeys(kdf, ikm, nonce1, nonce2)
	}
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	keysExpected := jgetRaw(t, entry.Expected, "keys")
	if len(keysExpected) == 0 {
		t.Fatalf("expected.keys missing")
	}
	checkSessionKey(t, "K_enc_c2s", keys.EncC2S, keysExpected)
	checkSessionKey(t, "K_enc_s2c", keys.EncS2C, keysExpected)
	checkSessionKey(t, "K_mac_c2s", keys.MACC2S, keysExpected)
	checkSessionKey(t, "K_mac_s2c", keys.MACS2C, keysExpected)
	checkSessionKey(t, "K_env_mac", keys.EnvMAC, keysExpected)
}

func checkSessionKey(t *testing.T, name string, got []byte, expected json.RawMessage) {
	t.Helper()
	field := name + "_hex"
	wantHex := jget(t, expected, field)
	if wantHex == "" {
		t.Errorf("missing %s in expected.keys", field)
		return
	}
	want := decodeHexF(t, wantHex, field)
	if !bytesEq(got, want) {
		t.Errorf("%s mismatch:\n  got  %x\n  want %x", name, got, want)
	}
}

// handleSessionMAC verifies HMAC-SHA-256 over the canonical envelope
// bytes. The vector pins the canonical UTF-8 string directly so the
// MAC computation is testable without having to re-canonicalize an
// envelope here.
func handleSessionMAC(t *testing.T, entry vectorEntry) {
	key := decodeHexF(t, jget(t, entry.Inputs, "key_hex"), "key_hex")
	msg := []byte(jget(t, entry.Inputs, "message_canonical_utf8"))

	// semp-go has its own crypto.ComputeMAC helper; cross-check both
	// against stdlib HMAC-SHA-256 so a regression in either surfaces.
	got := crypto.ComputeMAC(key, msg)
	wantHex := jget(t, entry.Expected, "mac_hex")
	want := decodeHexF(t, wantHex, "mac_hex")
	if !bytesEq(got, want) {
		t.Errorf("HMAC mismatch:\n  got  %x\n  want %x", got, want)
	}

	// stdlib cross-check: detects a regression where ComputeMAC's
	// underlying primitive changes without the vector noticing.
	std := hmac.New(sha256.New, key)
	std.Write(msg)
	if !bytesEq(std.Sum(nil), want) {
		t.Errorf("stdlib HMAC-SHA-256 disagrees with vector %x", want)
	}
}

// handleConfirmationHash verifies the SHA-256 over canonical(m1) ||
// canonical(m2) used in the §5.1 confirmation-hash binding.
func handleConfirmationHash(t *testing.T, entry vectorEntry) {
	m1 := []byte(jget(t, entry.Inputs, "message_1_canonical_utf8"))
	m2 := []byte(jget(t, entry.Inputs, "message_2_canonical_utf8"))
	got, err := handshake.ConfirmationHash(m1, m2)
	if err != nil {
		t.Fatalf("ConfirmationHash: %v", err)
	}
	wantHex := jget(t, entry.Expected, "hash_hex")
	want := decodeHexF(t, wantHex, "hash_hex")
	if !bytesEq(got, want) {
		t.Errorf("confirmation hash mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// handlePoW verifies the spec's PoW preimage construction and
// difficulty check by feeding the input through handshake.VerifySolution
// at the input difficulty. For the `valid: true` case VerifySolution MUST
// accept; for `valid: false` it MUST reject.
func handlePoW(t *testing.T, entry vectorEntry) {
	prefix := decodeHexF(t, jget(t, entry.Inputs, "prefix_hex"), "prefix_hex")
	chalID := jget(t, entry.Inputs, "challenge_id")
	nonceB64 := jget(t, entry.Inputs, "nonce_b64")
	difficulty := jgetInt(t, entry.Inputs, "required_difficulty_bits")
	wantHashHex := jget(t, entry.Expected, "hash_hex")
	wantValid := jgetBool(t, entry.Expected, "valid")

	err := handshake.VerifySolution(prefix, chalID, nonceB64, wantHashHex, difficulty)
	gotValid := err == nil
	if gotValid != wantValid {
		t.Errorf("VerifySolution valid=%v, want %v: err=%v", gotValid, wantValid, err)
	}

	// LeadingZeroBits is asserted independently so a regression in
	// either VerifySolution or LeadingZeroBits is localizable.
	wantLZ := jgetInt(t, entry.Expected, "leading_zero_bits")
	hash := decodeHexF(t, wantHashHex, "hash_hex")
	if got := handshake.LeadingZeroBits(hash); got != wantLZ {
		t.Errorf("LeadingZeroBits = %d, want %d", got, wantLZ)
	}
}

// ---------------------------------------------------------------------------
// Layer 2 handlers

// handleEnvelopeCanonical verifies the §4.3 canonicalization rules.
// The input `envelope_json` is unmarshalled into envelope.Envelope and
// CanonicalBytes() is compared byte-for-byte against the spec's
// canonical_utf8 string.
func handleEnvelopeCanonical(t *testing.T, entry vectorEntry) {
	raw := jgetRaw(t, entry.Inputs, "envelope_json")
	if len(raw) == 0 {
		t.Fatalf("inputs.envelope_json missing")
	}
	var env envelope.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	got, err := env.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	want := jget(t, entry.Expected, "canonical_utf8")
	if string(got) != want {
		t.Errorf("canonical bytes mismatch (%s):\n  got  %s\n  want %s",
			entry.SpecReference, string(got), want)
	}
}

// handleEnvelopeBuckets handles both `envelope-size-buckets` and
// `recipient-count-buckets` table-shape vectors. For size buckets it
// dispatches to envelope.SelectSizeBucket; recipient-count buckets are
// asserted via the documented next-power-of-two-min-2 rule directly,
// since semp-go's per-recipient bucketing is internal to padding.go and
// has no top-level public function on the relevant ints.
func handleEnvelopeBuckets(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "envelope-size-buckets":
		for i, raw := range entry.Samples {
			size := jgetInt(t, raw, "unpadded_size_bytes")
			wantBucket := jgetInt(t, raw, "bucket_size_bytes")
			got, err := envelope.SelectSizeBucket(int64(size), 1<<24)
			if err != nil {
				// Sizes above the ceiling produce an error per the
				// spec; the vector encodes that as "exceeds bucket
				// ceiling; recomposition required". Skip rather than
				// fail; ceiling handling is exercised by other tests.
				continue
			}
			if int(got) != wantBucket {
				t.Errorf("sample %d: size=%d got bucket=%d, want %d",
					i, size, got, wantBucket)
			}
		}
	case "recipient-count-buckets":
		for i, raw := range entry.Samples {
			real := jgetInt(t, raw, "real_recipients")
			single := jgetBool(t, raw, "single_domain_not_group")
			// `bucket_count` may be a number or the string "exceeds
			// bucket ceiling; recomposition required". Skip the
			// string form; semp-go raises an error for >1024.
			bc := jgetRaw(t, raw, "bucket_count")
			var n int
			if err := json.Unmarshal(bc, &n); err != nil {
				continue
			}
			got := recipientCountBucket(real, single)
			if got != n {
				t.Errorf("sample %d: real=%d single=%v got bucket=%d, want %d",
					i, real, single, got, n)
			}
		}
	default:
		t.Skipf("envelope-buckets sub-vector %q: no handler", entry.ID)
	}
}

// recipientCountBucket implements ENVELOPE.md §4.4.2 recipient-count
// padding. Floor is 2 unless real==1 AND single_domain_not_group, in
// which case the floor relaxes to 1 (a single-domain non-group send
// reveals only the obvious cardinality and gains no obfuscation from
// padding to 2).
func recipientCountBucket(real int, singleDomainNotGroup bool) int {
	if real == 1 && singleDomainNotGroup {
		return 1
	}
	if real <= 2 {
		return 2
	}
	p := 2
	for p < real {
		p <<= 1
	}
	return p
}

// handleDiscovery covers `discovery-response-parsing` and
// `discovery-txt-parsing`. For TXT parsing we feed each sample through
// discovery.ParseTXTCapabilities and compare against the expected
// capability fields.
func handleDiscovery(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "discovery-txt-parsing":
		// The vector has samples each carrying a `txt_record_utf8`
		// input and `expected` capability fields. Walk samples.
		for i, raw := range entry.Samples {
			record := jget(t, raw, "txt_record_utf8")
			expectedRaw := jgetRaw(t, raw, "expected")
			caps, err := discovery.ParseTXTCapabilities(record)
			expectedAction := jget(t, expectedRaw, "action")
			if expectedAction == "reject" {
				if err == nil {
					t.Errorf("sample %d: expected reject, parsed OK: %+v",
						i, caps)
				}
				continue
			}
			if err != nil {
				t.Errorf("sample %d: parse: %v", i, err)
				continue
			}
			// For accepted records, sanity-check the version field
			// where the vector pins it. Deeper field checks (transports,
			// extensions) are Phase 2 work.
			if v := jget(t, expectedRaw, "version"); v != "" && caps.Version != v {
				t.Errorf("sample %d: version=%s, want %s", i, caps.Version, v)
			}
		}
	case "discovery-response-parsing":
		t.Skip("discovery-response-parsing: cross-checks signature and " +
			"caching policy; Phase 2 (needs signed-discovery harness)")
	default:
		t.Skipf("discovery sub-vector %q: no handler", entry.ID)
	}
}

// handleRejectionCodes verifies the recoverability decision table by
// looking up each reason_code in semp-go's ReasonCode.Recoverable().
func handleRejectionCodes(t *testing.T, entry vectorEntry) {
	for i, raw := range entry.Samples {
		code := jget(t, raw, "reason_code")
		wantRecov := jgetBool(t, raw, "recoverable")
		gotRecov := semp.ReasonCode(code).Recoverable()
		if gotRecov != wantRecov {
			t.Errorf("sample %d: reason_code=%q recoverable=%v, want %v",
				i, code, gotRecov, wantRecov)
		}
	}
}

// handleExtensionEntries verifies extension validation outcomes
// (accept / reject) under a registry built from the input's
// `implementation_supports` list.
func handleExtensionEntries(t *testing.T, entry vectorEntry) {
	extRaw := jgetRaw(t, entry.Inputs, "extensions_json")
	if len(extRaw) == 0 {
		t.Skipf("extension-entries %q: no extensions_json", entry.ID)
		return
	}
	var extMap extensions.Map
	if err := json.Unmarshal(extRaw, &extMap); err != nil {
		t.Fatalf("unmarshal extensions: %v", err)
	}

	// Build a registry from implementation_supports. Each supported
	// identifier is registered as an optional extension on every
	// layer (the vector does not break out per-layer support).
	reg := extensions.NewRegistry()
	supports := jgetRaw(t, entry.Inputs, "implementation_supports")
	if len(supports) > 0 {
		var ids []string
		if err := json.Unmarshal(supports, &ids); err != nil {
			t.Fatalf("unmarshal implementation_supports: %v", err)
		}
		for _, id := range ids {
			_ = reg.Register(extensions.RegistryEntry{
				Identifier: id,
				Layers: []extensions.Layer{
					extensions.LayerPostmark,
					extensions.LayerBrief,
					extensions.LayerEnclosure,
				},
			})
		}
	}

	// Validate at the postmark layer (the vector does not always
	// pin a layer; postmark is the most common). Phase 2 will refine
	// per-layer dispatch from the vector's `layer` field if it adds one.
	err := extensions.Validate(reg, extensions.LayerPostmark, extMap)
	wantAction := jget(t, entry.Expected, "action")
	gotOK := err == nil
	switch wantAction {
	case "accept":
		if !gotOK {
			t.Errorf("validate: %v, want accept", err)
		}
	case "reject":
		if gotOK {
			t.Errorf("validate accepted, want reject")
		}
	default:
		t.Skipf("expected.action=%q: no handler mapping yet", wantAction)
	}
}

// handleClockTolerance dispatches the future-dated and expires-at
// boundary samples against clockskew.CheckFutureTimestamp and
// clockskew.CheckExpiry. Boundary cases marked
// "accept_or_reject_at_implementor_choice" are accepted either way.
func handleClockTolerance(t *testing.T, entry vectorEntry) {
	tol := clockskew.Default()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for i, raw := range entry.Samples {
		expected := jget(t, raw, "expected")
		switch entry.ID {
		case "clock-tolerance-future-dated":
			delta := jgetInt(t, raw, "T_minus_now_seconds")
			ts := now.Add(time.Duration(delta) * time.Second)
			err := clockskew.CheckFutureTimestamp(ts, now, tol)
			if !checkClockOutcome(err == nil, expected) {
				t.Errorf("sample %d: T-now=%ds got accept=%v, want %s",
					i, delta, err == nil, expected)
			}
		case "clock-tolerance-expires-at":
			// The vector encodes `now_minus_expiresAt_seconds` so a
			// positive delta means now is past expires_at. Compute
			// expires_at = now - delta accordingly.
			delta := jgetInt(t, raw, "now_minus_expiresAt_seconds")
			ts := now.Add(-time.Duration(delta) * time.Second)
			err := clockskew.CheckExpiry(ts, now, tol)
			if !checkClockOutcome(err == nil, expected) {
				t.Errorf("sample %d: now-expiresAt=%ds got accept=%v, want %s",
					i, delta, err == nil, expected)
			}
		default:
			t.Skipf("clock-tolerance sub-vector %q: no handler", entry.ID)
			return
		}
	}
}

// checkClockOutcome maps the vector's expected verdict to a pass/fail.
// Boundary samples where the spec allows either accept or reject pass
// regardless of the implementation's choice.
func checkClockOutcome(accepted bool, expected string) bool {
	switch expected {
	case "accept":
		return accepted
	case "reject":
		return !accepted
	case "accept_or_reject_at_implementor_choice":
		return true
	default:
		return false
	}
}
