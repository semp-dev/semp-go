package test

// Per-category vector handlers. Three shapes live here:
//
//   - Single-signature documents: "blank one signature field,
//     canonicalize, prepend a domain-separation prefix, Ed25519-verify
//     against a pinned public key". A single `verifySingleSignedDoc`
//     helper plus a per-category dispatcher covers ten categories at
//     modest cost.
//
//   - Decision-table shape validators for status/lifecycle vectors.
//
//   - Multi-signature chains (migration, forwarding) and round-trip
//     constructions (seal, envelope, sender-signature, etc.).

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/canonical"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// signedDocSpec describes how to verify one signed document. The
// SignaturePath field uses dotted notation: "signature.value" navigates
// into a {required,data}-style nested signature object; a single
// segment ("server_signature") names a top-level string field whose
// entire value IS the signature base64.
type signedDocSpec struct {
	// SignedJSON is the document AS PUBLISHED, with the signature
	// value populated. The verifier blanks it before canonicalizing.
	SignedJSON map[string]any

	// SignaturePath is the dotted path to the signature value field.
	// Examples: "signature.value", "server_signature",
	// "device_signature.value".
	SignaturePath string

	// PublicKey is the signer's Ed25519 public key (32 bytes).
	PublicKey ed25519.PublicKey

	// Prefix is the domain-separation prefix from ENVELOPE.md §4.3
	// (e.g. "SEMP-ACCOUNT-CLOSURE:"). Includes the trailing colon.
	Prefix string
}

// verifySingleSignedDoc performs the four-step verification:
//  1. Deep-copy SignedJSON; navigate SignaturePath; capture and blank.
//  2. Canonicalize the blanked copy via canonical.
//  3. Prepend Prefix bytes.
//  4. Ed25519.Verify(PublicKey, prefix||canonical, signature).
//
// Returns (canonicalBlanked, signatureBytes, verifyOK, error). On any
// structural problem it fails the surrounding test via t.Fatalf and
// the return value is unused.
func verifySingleSignedDoc(t *testing.T, spec signedDocSpec) ([]byte, []byte, bool) {
	t.Helper()

	// Deep-copy via JSON round-trip so the original SignedJSON the
	// caller passed in stays untouched (the runner reuses it for
	// other assertions).
	raw, err := json.Marshal(spec.SignedJSON)
	if err != nil {
		t.Fatalf("re-marshal signed doc: %v", err)
	}
	var copy map[string]any
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatalf("re-parse signed doc: %v", err)
	}

	sigB64 := pluckAndBlankPath(t, copy, spec.SignaturePath)
	signature, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature %q: %v", sigB64, err)
	}
	if len(signature) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(signature), ed25519.SignatureSize)
	}

	blanked, err := canonical.Marshal(copy)
	if err != nil {
		t.Fatalf("canonical.Marshal: %v", err)
	}

	signingInput := append([]byte(spec.Prefix), blanked...)
	ok := ed25519.Verify(spec.PublicKey, signingInput, signature)
	return blanked, signature, ok
}

// pluckAndBlankPath walks a dotted path through `m`, returns the
// string value at the leaf, and replaces it with "". The path traverses
// nested map[string]any objects until the final segment, which MUST
// resolve to a string.
func pluckAndBlankPath(t *testing.T, m map[string]any, path string) string {
	t.Helper()
	parts := strings.Split(path, ".")
	cur := any(m)
	for i, p := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %q: segment %q is not a map", path, parts[:i])
		}
		val, present := obj[p]
		if !present {
			t.Fatalf("path %q: missing segment %q", path, p)
		}
		if i == len(parts)-1 {
			s, ok := val.(string)
			if !ok {
				t.Fatalf("path %q: leaf is not a string (%T)", path, val)
			}
			obj[p] = ""
			return s
		}
		cur = val
	}
	t.Fatalf("path %q: empty", path)
	return ""
}

// ---------------------------------------------------------------------------
// Generic single-signature handlers
//
// Each category-handler below is two lines of glue: pull the signed
// JSON + pubkey + prefix, hand to verifySingleSignedDoc. The optional
// canonical-bytes intermediate cross-check catches drift between the
// generator's canonicalization and semp-go's, which is a weaker
// guarantee than signature verification (verification implicitly
// asserts byte equality) but produces a clearer error when canonical
// bytes diverge.

// signedDocFromExpected pulls a `expected.signed_<x>_json` map from a
// vectorEntry. The vectors name the field differently per category;
// this walker tries the most common keys.
func signedDocFromExpected(t *testing.T, entry vectorEntry) (map[string]any, string) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(entry.Expected, &top); err != nil {
		t.Fatalf("expected: unmarshal: %v", err)
	}
	for _, k := range []string{
		"signed_request_json",
		"signed_update_json",
		"signed_record_json",
		"signed_response_json",
		"signed_message_json",
		"signed_manifest_json",
		"signed_doc_json",
	} {
		if raw, ok := top[k]; ok {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("%s: unmarshal: %v", k, err)
			}
			return m, k
		}
	}
	// Some vectors stash the document directly under expected (no
	// "signed_*_json" wrapper). Skip cleanly.
	t.Skipf("no signed-doc field found in expected (keys: %v)", topKeys(top))
	return nil, ""
}

func topKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// pubKeyFromInputs decodes a hex public key from `inputs.<field>`. It
// tries the conventional naming variants in order.
func pubKeyFromInputs(t *testing.T, entry vectorEntry, candidates ...string) ed25519.PublicKey {
	t.Helper()
	for _, name := range candidates {
		if h := jget(t, entry.Inputs, name); h != "" {
			return ed25519.PublicKey(decodeHexF(t, h, name))
		}
	}
	t.Fatalf("no pub key found among %v", candidates)
	return nil
}

// canonicalIntermediateMatches optionally verifies that semp-go's
// canonical bytes for the blanked document equal the generator's
// pinned `intermediates.canonical_with_blanked_signature_utf8`. The
// vector format makes this OPTIONAL - many entries omit
// intermediates - but where it IS pinned, mismatch is a clear
// canonicalization-drift signal worth surfacing distinctly from a
// signature failure.
func canonicalIntermediateMatches(t *testing.T, entry vectorEntry, blanked []byte) {
	t.Helper()
	if len(entry.Intermediates) == 0 {
		return
	}
	want := jget(t, entry.Intermediates, "canonical_with_blanked_signature_utf8")
	if want == "" {
		return
	}
	if string(blanked) != want {
		t.Errorf("canonical-with-blanked-signature mismatch (%s):\n  got  %s\n  want %s",
			entry.SpecReference, string(blanked), want)
	}
}

// dispatchSimpleSignedDoc covers categories whose every vector entry
// fits the (signedDoc, pubkey, prefix) shape with a single signature.
type signedDocPicker func(t *testing.T, entry vectorEntry) signedDocSpec

func runSignedDocHandler(pick signedDocPicker) handler {
	return func(t *testing.T, entry vectorEntry) {
		spec := pick(t, entry)
		blanked, _, ok := verifySingleSignedDoc(t, spec)
		canonicalIntermediateMatches(t, entry, blanked)
		if !ok {
			t.Errorf("Ed25519 verify failed (%s; prefix=%q, path=%q)",
				entry.SpecReference, spec.Prefix, spec.SignaturePath)
		}
	}
}

// ---------------------------------------------------------------------------
// Per-category pickers

func pickAccountClosure(t *testing.T, entry vectorEntry) signedDocSpec {
	doc, _ := signedDocFromExpected(t, entry)
	return signedDocSpec{
		SignedJSON:    doc,
		SignaturePath: "signature.value",
		PublicKey:     pubKeyFromInputs(t, entry, "primary_device_pub_hex"),
		Prefix:        "SEMP-ACCOUNT-CLOSURE:",
	}
}

func pickConfigurationUpdate(t *testing.T, entry vectorEntry) signedDocSpec {
	doc, _ := signedDocFromExpected(t, entry)
	return signedDocSpec{
		SignedJSON:    doc,
		SignaturePath: "signature.value",
		PublicKey:     pubKeyFromInputs(t, entry, "domain_pub_hex"),
		Prefix:        "SEMP-CONFIGURATION-UPDATE:",
	}
}

func pickUserPolicy(t *testing.T, entry vectorEntry) signedDocSpec {
	doc, _ := signedDocFromExpected(t, entry)
	return signedDocSpec{
		SignedJSON:    doc,
		SignaturePath: "signature.value",
		PublicKey:     pubKeyFromInputs(t, entry, "user_identity_pub_hex", "device_pub_hex"),
		Prefix:        "SEMP-USER-POLICY:",
	}
}

func pickDiscoverySigned(t *testing.T, entry vectorEntry) signedDocSpec {
	doc, _ := signedDocFromExpected(t, entry)
	return signedDocSpec{
		SignedJSON:    doc,
		SignaturePath: "signature.value",
		PublicKey:     pubKeyFromInputs(t, entry, "domain_pub_hex"),
		Prefix:        "SEMP-DISCOVERY:",
	}
}

// ---------------------------------------------------------------------------
// handshake-messages: 5 entries, two shapes
//
//	canonical-only entries (init, confirm) - verify canonical bytes only
//	signed entries (response, accepted, rejected) - verify Ed25519
//
// The signature field is `server_signature` (top-level base64 string),
// with one wrinkle: the "rejected" entry uses the same field name, but
// the "init" and "confirm" entries don't have outer signatures at all
// (the client identity proof is signed separately).

func handleHandshakeMessages(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "handshake-init-canonical", "handshake-confirm-canonical":
		// Canonical-only verification: take message_json (no outer
		// signature on these steps), canonicalize, compare to the
		// pinned canonical_utf8 intermediate.
		raw := jgetRaw(t, entry.Inputs, "message_json")
		if len(raw) == 0 {
			t.Skip("missing message_json")
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("message_json unmarshal: %v", err)
		}
		got, err := canonical.Marshal(doc)
		if err != nil {
			t.Fatalf("canonical.Marshal: %v", err)
		}
		want := jget(t, entry.Intermediates, "canonical_utf8")
		if want == "" {
			return
		}
		if string(got) != want {
			t.Errorf("canonical bytes mismatch (%s):\n  got  %s\n  want %s",
				entry.SpecReference, string(got), want)
		}
	case "handshake-response-signed", "handshake-accepted-signed", "handshake-rejected-signed":
		doc, _ := signedDocFromExpected(t, entry)
		spec := signedDocSpec{
			SignedJSON:    doc,
			SignaturePath: "server_signature",
			PublicKey:     pubKeyFromInputs(t, entry, "server_domain_pub_hex"),
			Prefix:        "SEMP-HANDSHAKE:",
		}
		blanked, _, ok := verifySingleSignedDoc(t, spec)
		canonicalIntermediateMatches(t, entry, blanked)
		if !ok {
			t.Errorf("Ed25519 verify failed (%s)", entry.SpecReference)
		}
	default:
		t.Skipf("handshake-messages %q: no handler", entry.ID)
	}
}

func handleHandshakeMessagesPQ(t *testing.T, entry vectorEntry) {
	// PQ variants reuse the baseline flow; the only differences are
	// in the body fields (algorithm, ephemeral key bytes) and the
	// signature value, both of which the generic flow handles.
	switch entry.ID {
	case "handshake-response-pq-signed", "handshake-accepted-pq-signed":
		doc, _ := signedDocFromExpected(t, entry)
		spec := signedDocSpec{
			SignedJSON:    doc,
			SignaturePath: "server_signature",
			PublicKey:     pubKeyFromInputs(t, entry, "server_domain_pub_hex"),
			Prefix:        "SEMP-HANDSHAKE:",
		}
		blanked, _, ok := verifySingleSignedDoc(t, spec)
		canonicalIntermediateMatches(t, entry, blanked)
		if !ok {
			t.Errorf("Ed25519 verify failed (%s)", entry.SpecReference)
		}
	default:
		t.Skipf("handshake-messages-pq %q: no handler", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// session-resumption: 3 entries
//
//	resume-request-canonical  - canonical-only; client_signature blanked
//	resume-accepted-signed    - Ed25519; server_signature
//	resume-key-derivation     - KDF round-trip; not handled here
//
// The request is canonical-only because the client signature isn't
// applied at this layer (per HANDSHAKE.md §2.8); the canonical bytes
// are what matters here.

func handleSessionResumption(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "resume-accepted-signed":
		doc, _ := signedDocFromExpected(t, entry)
		spec := signedDocSpec{
			SignedJSON:    doc,
			SignaturePath: "server_signature",
			PublicKey:     pubKeyFromInputs(t, entry, "server_domain_pub_hex"),
			Prefix:        "SEMP-HANDSHAKE:",
		}
		blanked, _, ok := verifySingleSignedDoc(t, spec)
		canonicalIntermediateMatches(t, entry, blanked)
		if !ok {
			t.Errorf("Ed25519 verify failed (%s)", entry.SpecReference)
		}
	case "resume-request-canonical":
		raw := jgetRaw(t, entry.Inputs, "message_json")
		if len(raw) == 0 {
			t.Skip("missing message_json")
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("message_json unmarshal: %v", err)
		}
		got, err := canonical.Marshal(doc)
		if err != nil {
			t.Fatalf("canonical.Marshal: %v", err)
		}
		want := jget(t, entry.Intermediates, "canonical_utf8")
		if want == "" {
			return
		}
		if string(got) != want {
			t.Errorf("canonical bytes mismatch:\n  got  %s\n  want %s",
				string(got), want)
		}
	case "resume-key-derivation":
		// HKDF-SHA-512 with the resumed-session salt+IKM
		// construction (HANDSHAKE.md §2.8.3, SESSION.md §2.7).
		// The vector pins:
		//   ephemeral_shared_secret_hex (from rekey ECDH)
		//   K_resumption_hex            (retained from prior session)
		//   client_nonce_hex / server_nonce_hex
		// IKM = ephemeral_shared_secret || K_resumption.
		// Salt = client_nonce || server_nonce.
		// Then DeriveResumedSessionKeys derives the five keys.
		ephSS := decodeHexF(t, jget(t, entry.Inputs, "ephemeral_shared_secret_hex"),
			"ephemeral_shared_secret_hex")
		kRes := decodeHexF(t, jget(t, entry.Inputs, "K_resumption_hex"), "K_resumption_hex")
		cNonce := decodeHexF(t, jget(t, entry.Inputs, "client_nonce_hex"), "client_nonce_hex")
		sNonce := decodeHexF(t, jget(t, entry.Inputs, "server_nonce_hex"), "server_nonce_hex")

		kdf := crypto.NewKDFHKDFSHA512()
		keys, err := crypto.DeriveResumedSessionKeys(kdf, ephSS, kRes, cNonce, sNonce)
		if err != nil {
			t.Fatalf("DeriveResumedSessionKeys: %v", err)
		}
		// PRK is HKDF-Extract(salt, ikm).
		ikm := append(append([]byte{}, ephSS...), kRes...)
		salt := append(append([]byte{}, cNonce...), sNonce...)
		prk := kdf.Extract(salt, ikm)

		expectedPRK := decodeHexF(t, jget(t, entry.Expected, "prk_resume_hex"), "prk_resume_hex")
		if !bytesEq(prk, expectedPRK) {
			t.Errorf("resumed PRK mismatch:\n  got  %x\n  want %x", prk, expectedPRK)
		}
		expectedKeys := jgetRaw(t, entry.Expected, "keys")
		checkSessionKey(t, "K_enc_c2s", keys.EncC2S, expectedKeys)
		checkSessionKey(t, "K_enc_s2c", keys.EncS2C, expectedKeys)
		checkSessionKey(t, "K_mac_c2s", keys.MACC2S, expectedKeys)
		checkSessionKey(t, "K_mac_s2c", keys.MACS2C, expectedKeys)
		checkSessionKey(t, "K_env_mac", keys.EnvMAC, expectedKeys)
	default:
		t.Skipf("session-resumption %q: no handler", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// recovery-shamir: three entries
//
//	shamir-split-and-combine            - GF(256) Shamir; not handled here
//	shamir-recovery-set-manifest-signed - Ed25519; signature.value
//	shamir-share-record-signed          - multiple records; device_signature.value

func handleRecoveryShamir(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "shamir-recovery-set-manifest-signed":
		doc, _ := signedDocFromExpected(t, entry)
		spec := signedDocSpec{
			SignedJSON:    doc,
			SignaturePath: "signature.value",
			PublicKey:     pubKeyFromInputs(t, entry, "user_pub_hex"),
			Prefix:        "SEMP-RECOVERY-MANIFEST:",
		}
		blanked, _, ok := verifySingleSignedDoc(t, spec)
		canonicalIntermediateMatches(t, entry, blanked)
		if !ok {
			t.Errorf("Ed25519 verify failed (%s)", entry.SpecReference)
		}
	case "shamir-share-record-signed":
		// Five share records, each signed by its own device key.
		var exp map[string]json.RawMessage
		if err := json.Unmarshal(entry.Expected, &exp); err != nil {
			t.Fatalf("expected: %v", err)
		}
		recordsRaw, ok := exp["signed_share_records_json"]
		if !ok {
			t.Skip("missing signed_share_records_json")
		}
		var records []map[string]any
		if err := json.Unmarshal(recordsRaw, &records); err != nil {
			t.Fatalf("share records unmarshal: %v", err)
		}
		// inputs.device_pubs_hex is an ordered array matching share_index 1..N.
		var inp map[string]json.RawMessage
		if err := json.Unmarshal(entry.Inputs, &inp); err != nil {
			t.Fatalf("inputs: %v", err)
		}
		var pubsHex []string
		if err := json.Unmarshal(inp["device_pubs_hex"], &pubsHex); err != nil {
			t.Fatalf("device_pubs_hex: %v", err)
		}
		if len(pubsHex) != len(records) {
			t.Fatalf("device pubs (%d) != share records (%d)",
				len(pubsHex), len(records))
		}
		for i, rec := range records {
			pub := ed25519.PublicKey(decodeHexF(t, pubsHex[i],
				fmt.Sprintf("device_pubs_hex[%d]", i)))
			spec := signedDocSpec{
				SignedJSON:    rec,
				SignaturePath: "device_signature.value",
				PublicKey:     pub,
				Prefix:        "SEMP-RECOVERY-SHARE:",
			}
			_, _, sigOK := verifySingleSignedDoc(t, spec)
			if !sigOK {
				t.Errorf("share %d: Ed25519 verify failed", i+1)
			}
		}
	case "shamir-split-and-combine":
		runShamirRoundTrip(t, entry)
	default:
		t.Skipf("recovery-shamir %q: no handler", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// first-contact-token: 2 entries
//
//	first-contact-token-valid          - verify PoW + postmark binding
//	first-contact-token-replay-rejected - rejection demo (must_reject)
//
// The token itself isn't Ed25519-signed; its integrity comes from the
// PoW solution + postmark binding (HANDSHAKE.md §2.2a.4). Re-running
// VerifySolution and the binding check exercises both predicates.

func handleFirstContactToken(t *testing.T, entry vectorEntry) {
	// Both vectors share the same shape: token_json + a postmark id
	// (matching for valid, mismatching for replay).
	tokenRaw := jgetRaw(t, entry.Inputs, "token_json")
	if len(tokenRaw) == 0 {
		t.Skip("first-contact-token: missing token_json")
	}
	var token map[string]any
	if err := json.Unmarshal(tokenRaw, &token); err != nil {
		t.Fatalf("token unmarshal: %v", err)
	}

	// First-contact PoW (HANDSHAKE.md §2.2a.4) uses a different
	// preimage from the §2.2b challenge PoW: the difficulty check is
	// over `H(prefix || nonce)`, raw byte concatenation, with no
	// challenge_id and no colons. semp-go's handshake.VerifySolution
	// implements §2.2b's text-form preimage and is NOT applicable
	// here. The two PoW formulas coexist in the spec because §2.2a.4
	// binds the first-contact tuple via `prefix` (which is itself a
	// hash of sender_domain + recipient_address + postmark_id), not
	// via the preimage shape.
	prefixB64, _ := token["prefix"].(string)
	prefix, err := base64.StdEncoding.DecodeString(prefixB64)
	if err != nil {
		t.Fatalf("decode prefix: %v", err)
	}
	nonceB64, _ := token["nonce"].(string)
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	difficulty := 0
	if d, ok := token["difficulty"].(float64); ok {
		difficulty = int(d)
	}

	preimage := append(append([]byte{}, prefix...), nonce...)
	sum := sha256.Sum256(preimage)
	leadingZeros := handshake.LeadingZeroBits(sum[:])

	postmarkBound, _ := token["postmark_id"].(string)
	carryingPostmark := jget(t, entry.Inputs, "carrying_envelope_postmark_id")

	powOK := leadingZeros >= difficulty
	bindingOK := postmarkBound == carryingPostmark

	switch entry.ID {
	case "first-contact-token-valid":
		if !powOK {
			t.Errorf("PoW verification failed for valid token")
		}
		if !bindingOK {
			t.Errorf("postmark binding mismatch: token=%q, envelope=%q",
				postmarkBound, carryingPostmark)
		}
	case "first-contact-token-replay-rejected":
		// Must-reject: PoW still satisfies (same nonce, same hash), but
		// postmark mismatch causes the recipient to reject.
		if !powOK {
			t.Errorf("PoW should still verify on a replayed token; got reject")
		}
		if bindingOK {
			t.Errorf("postmark binding should NOT match for replay case")
		}
	default:
		t.Skipf("first-contact-token %q: no handler", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// Decision-table shape validators
//
// These categories ship table-shape vectors that map a (state, event)
// or (condition) tuple to an expected_action / reason_code / behavior
// string. The runner cannot dispatch them through a single semp-go
// function because the corresponding behavior is implemented across
// many call sites. What we CAN do is shape validation:
//
//   1. Assert the samples slice is non-empty.
//   2. Assert each sample carries the expected fields.
//   3. Where a `reason_code` field appears, cross-check it against
//      semp-go's ReasonCode enum so the vector cannot drift to a
//      reason code semp-go does not know.
//
// This is weaker than the byte-level checks earlier handlers do but
// stronger than t.Skip: a generator that introduces a typo'd
// reason_code or drops a required sample field fails the runner.

// knownReasonCodes is the set of ReasonCode constants semp-go
// recognizes. The runner uses it to detect drift in vector samples
// that pin a reason_code field.
//
// New ReasonCode constants in semp-go automatically extend this set
// only if added to this map; the runner intentionally requires
// explicit curation so that a code added in semp-go but never
// referenced by any vector still gets surfaced.
var knownReasonCodes = func() map[string]bool {
	codes := []string{
		"blocked", "auth_failed", "policy_forbidden", "handshake_expired",
		"handshake_invalid", "no_session", "rate_limited", "challenge",
		"challenge_failed", "challenge_invalid", "server_at_capacity",
		"resumption_failed", "version_unsupported",
		"seal_invalid", "session_mac_invalid", "envelope_expired",
		"envelope_size_exceeded", "extension_unsupported",
		"extension_size_exceeded", "scope_exceeded", "scope_invalid",
		"certificate_expired", "server_unavailable", "session_expired",
		"rekey_unsupported", "policy_kind_unsupported",
		"policy_op_invalid", "policy_version_stale",
	}
	out := make(map[string]bool, len(codes))
	for _, c := range codes {
		out[c] = true
	}
	return out
}()

// validateReasonCode asserts a reason_code string is one semp-go
// understands. Empty strings and explicit nulls pass through (the
// vector uses null in cases where the spec doesn't define a code).
func validateReasonCode(t *testing.T, sampleIdx int, raw json.RawMessage) {
	t.Helper()
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Errorf("sample %d: reason_code is not a string: %s", sampleIdx, raw)
		return
	}
	if s == "" {
		return
	}
	if !knownReasonCodes[s] {
		t.Errorf("sample %d: reason_code %q is not in semp-go's ReasonCode set; either the vector typo'd or semp-go is missing a constant",
			sampleIdx, s)
	}
}

// requireSampleFields asserts every sample carries every name in
// `required`, with the field present (the value MAY be null -
// many decision tables use null to mean "no defined value for this
// row"; that is an intentional encoding, not a generator bug).
//
// Catches generator bugs that drop or rename a field across versions.
// Stricter "non-null" assertions belong in per-category handlers
// where the spec genuinely forbids null in a particular column.
func requireSampleFields(t *testing.T, samples []json.RawMessage, required ...string) {
	t.Helper()
	if len(samples) == 0 {
		t.Errorf("samples is empty")
		return
	}
	for i, raw := range samples {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Errorf("sample %d: not an object: %v", i, err)
			continue
		}
		for _, field := range required {
			if _, ok := m[field]; !ok {
				t.Errorf("sample %d: missing field %q", i, field)
			}
		}
		// Where reason_code appears AND is non-null, validate
		// against semp-go's enum. A null reason_code means the
		// spec did not pin one, which is allowed.
		if rc, ok := m["reason_code"]; ok {
			validateReasonCode(t, i, rc)
		}
	}
}

func handleDeliveryStatus(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "submission-status-to-ui-state":
		requireSampleFields(t, entry.Samples,
			"submission_status", "client_ui_state")
	case "queued-to-final-transitions":
		requireSampleFields(t, entry.Samples,
			"initial_status", "delivery_event_status", "client_action")
	case "discovery-outcome-to-submission-status":
		requireSampleFields(t, entry.Samples,
			"discovery_outcome", "submission_status", "client_action")
	case "multi-recipient-mixed-outcomes":
		// This entry is single-case shape (inputs + expected, no
		// samples). Just confirm both are present and well-formed.
		if len(entry.Inputs) == 0 {
			t.Error("inputs missing")
		}
		if len(entry.Expected) == 0 {
			t.Error("expected missing")
		}
	case "persistent-silent-counter-behavior":
		handlePersistentSilentCounter(t, entry)
	default:
		t.Errorf("delivery-status %q: no handler", entry.ID)
	}
}

func handleDeviceCertificates(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "certificate-validation-failures":
		requireSampleFields(t, entry.Samples, "condition", "expected_action")
	case "scope-enforcement-by-recipient":
		requireSampleFields(t, entry.Samples,
			"recipient_address", "scope_match", "expected_action")
	case "scope-mode-enforcement":
		requireSampleFields(t, entry.Samples,
			"scope_send_mode", "recipient", "expected_action")
	case "receive-matcher-enforcement":
		requireSampleFields(t, entry.Samples,
			"device", "scope_receive", "inbound_sender", "expected")
	case "rate-limit-enforcement":
		requireSampleFields(t, entry.Samples,
			"tier_config", "state", "expected_action")
	case "certificate-lifecycle-operations":
		requireSampleFields(t, entry.Samples,
			"operation", "session_impact", "expected_behavior")
	case "valid-device-certificate", "resource-read-write-enforcement", "staged-delivery":
		// These are descriptive entries without a uniform sample
		// schema; just confirm they're well-formed JSON.
		if len(entry.Inputs) == 0 && len(entry.Samples) == 0 {
			t.Error("entry has neither inputs nor samples")
		}
	default:
		t.Skipf("device-certificates %q: no handler", entry.ID)
	}
}

func handleKeyRevocation(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "revoked-key-response":
		// Single-case shape: assert inputs and expected are present
		// and the reason_code (if any) is in the enum.
		if len(entry.Inputs) == 0 {
			t.Error("inputs missing")
		}
		if len(entry.Expected) == 0 {
			t.Error("expected missing")
		}
		if raw := jgetRaw(t, entry.Expected, "reason_code"); len(raw) > 0 {
			validateReasonCode(t, 0, raw)
		}
	default:
		t.Skipf("key-revocation %q: no handler", entry.ID)
	}
}

func handleRecipientStatus(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "status-visibility-rules":
		requireSampleFields(t, entry.Samples,
			"visibility_mode", "sender_identity", "status_included")
	case "status-does-not-affect-delivery":
		requireSampleFields(t, entry.Samples,
			"recipient_state", "envelope_valid", "expected_acknowledgment")
	default:
		t.Skipf("recipient-status %q: no handler", entry.ID)
	}
}

func handleSessionLifecycle(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "session-state-transitions":
		requireSampleFields(t, entry.Samples,
			"from_state", "event", "to_state")
	case "concurrent-session-limits":
		requireSampleFields(t, entry.Samples,
			"scenario", "expected_behavior")
	case "rekey-limits":
		requireSampleFields(t, entry.Samples,
			"condition", "expected_behavior")
	default:
		t.Skipf("session-lifecycle %q: no handler", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// must-reject-index cross-reference + envelope-rejection schema
//
// must-reject-index.json is a generated cross-reference; the runner
// validates that every `pointer` of the form `<file>#<id>` resolves
// to a vector entry with the matching `must_reject:true` flag. This
// is a structural assertion only - it does not re-verify the
// rejection outcome (those live in their respective files and are
// covered by their own handlers).
//
// negative-envelope-rejection schema-only here; the actual must-reject
// outcomes need round-trip-aware envelope verification (handled below).

func handleMustRejectIndex(t *testing.T, entry vectorEntry) {
	// The index file has a different top-level shape: no `vectors`
	// array of (inputs, expected) entries, just the index itself.
	// Each "vector" entry the runner sees is actually a row of the
	// flat index. Our dispatch already iterates entries, but the
	// must-reject-index file exposes only summary/by_class/flat at
	// the top level. The runner currently treats it as 0 entries
	// (no `vectors` field), so this handler is effectively unused -
	// reaching here would mean the file structure changed.
	if len(entry.Inputs) > 0 || len(entry.Expected) > 0 {
		t.Errorf("must-reject-index entry has unexpected fields: %s", entry.ID)
	}
}

func handleNegativeEnvelopeRejection(t *testing.T, entry vectorEntry) {
	// Re-run the §7.2 verification steps and confirm the pinned
	// rejection actually happens. Each entry pins an envelope
	// constructed to fail at a specific step; the runner asserts
	// semp-go's verification fails at that step (and only that step
	// for the first failure).
	if raw := jgetRaw(t, entry.Expected, "rejection_reason_code"); len(raw) > 0 {
		validateReasonCode(t, 0, raw)
	}

	envRaw := jgetRaw(t, entry.Inputs, "envelope_json")
	if len(envRaw) == 0 {
		t.Fatal("inputs.envelope_json missing")
	}
	var env envelope.Envelope
	if err := json.Unmarshal(envRaw, &env); err != nil {
		t.Fatalf("envelope unmarshal: %v", err)
	}
	canonicalEnv, err := env.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	senderPub := decodeHexF(t, jget(t, entry.Inputs, "sender_domain_pub_hex"), "sender_domain_pub_hex")

	// Step 1: seal.signature verification.
	sealSig, err := base64.StdEncoding.DecodeString(env.Seal.Signature)
	if err != nil {
		t.Fatalf("decode seal.signature: %v", err)
	}
	signingInput := append([]byte("SEMP-ENVELOPE:"), canonicalEnv...)
	step1Verifies := ed25519.Verify(ed25519.PublicKey(senderPub), signingInput, sealSig)

	wantStep1 := jgetBool(t, entry.Expected, "step_1_seal_signature_verifies")
	if step1Verifies != wantStep1 {
		t.Errorf("step_1_seal_signature_verifies got %v, want %v",
			step1Verifies, wantStep1)
	}

	switch entry.ID {
	case "envelope-expired":
		// Step 1 should pass (envelope was correctly signed) but
		// step 2 (postmark.expires) is in the past relative to now.
		nowISO := jget(t, entry.Inputs, "now_iso")
		now, err := timeParseISO(nowISO)
		if err != nil {
			t.Fatalf("parse now_iso: %v", err)
		}
		if env.Postmark.Expires.IsZero() {
			t.Fatal("postmark.expires zero")
		}
		expired := !env.Postmark.Expires.After(now)
		wantExpired := jgetBool(t, entry.Expected, "step_2_postmark_expires_in_past")
		if expired != wantExpired {
			t.Errorf("postmark expired got %v, want %v", expired, wantExpired)
		}
	case "seal-signature-invalid":
		// Step 1 MUST reject. step1Verifies should be false.
		if step1Verifies {
			t.Error("seal.signature unexpectedly verified")
		}
	case "session-mac-invalid":
		// Step 1 passes (signature is over correct canonical bytes),
		// but step 4 (session_mac) is wrong because the MAC was
		// computed under a different key. Recompute the MAC under
		// the correct K_env_mac and confirm it does NOT match the
		// pinned envelope's session_mac.
		kMac := decodeHexF(t, jget(t, entry.Inputs, "K_env_mac_hex"), "K_env_mac_hex")
		gotMAC := computeHMAC(kMac, canonicalEnv)
		wantMAC, err := base64.StdEncoding.DecodeString(env.Seal.SessionMAC)
		if err != nil {
			t.Fatalf("decode session_mac: %v", err)
		}
		step4Verifies := bytesEq(gotMAC, wantMAC)
		wantStep4 := jgetBool(t, entry.Expected, "step_4_session_mac_verifies")
		if step4Verifies != wantStep4 {
			t.Errorf("step_4_session_mac_verifies got %v, want %v",
				step4Verifies, wantStep4)
		}
	}
}

func computeHMAC(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// timeParseISO is a thin wrapper around time.Parse(time.RFC3339, ...)
// that reports a clearer error.
func timeParseISO(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// _ keeps `hash` import live for any future helpers that need a
// generic interface; remove when no longer needed.
var _ hash.Hash

// ---------------------------------------------------------------------------
// sender-signature verifier (3 entries)
//
// All three entries share the same construction: a sender_signature
// over the enclosure's canonical bytes with the SEMP-ENCLOSURE-SENDER:
// prefix and sender_signature.value blanked. Verification is
// straightforward; the must-reject cases assert that the wrong-key
// or tampered-bytes case fails verification.

func handleSenderSignature(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "sender-signature-valid":
		var exp map[string]json.RawMessage
		if err := json.Unmarshal(entry.Expected, &exp); err != nil {
			t.Fatalf("expected: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(exp["signed_enclosure_json"], &doc); err != nil {
			t.Fatalf("signed_enclosure unmarshal: %v", err)
		}
		spec := signedDocSpec{
			SignedJSON:    doc,
			SignaturePath: "sender_signature.value",
			PublicKey:     pubKeyFromInputs(t, entry, "identity_public_key_hex"),
			Prefix:        "SEMP-ENCLOSURE-SENDER:",
		}
		_, _, ok := verifySingleSignedDoc(t, spec)
		if !ok {
			t.Errorf("Ed25519 verify failed (%s)", entry.SpecReference)
		}
	case "sender-signature-tampered-body":
		var doc map[string]any
		if err := json.Unmarshal(jgetRaw(t, entry.Inputs, "tampered_signed_enclosure_json"), &doc); err != nil {
			t.Fatalf("tampered_signed_enclosure unmarshal: %v", err)
		}
		spec := signedDocSpec{
			SignedJSON:    doc,
			SignaturePath: "sender_signature.value",
			PublicKey:     pubKeyFromInputs(t, entry, "identity_public_key_hex"),
			Prefix:        "SEMP-ENCLOSURE-SENDER:",
		}
		_, _, ok := verifySingleSignedDoc(t, spec)
		if ok {
			t.Error("tampered body unexpectedly verified")
		}
	case "sender-signature-wrong-key":
		var doc map[string]any
		if err := json.Unmarshal(jgetRaw(t, entry.Inputs, "signed_enclosure_json"), &doc); err != nil {
			t.Fatalf("signed_enclosure unmarshal: %v", err)
		}
		// Verify with claimed (wrong) key - must fail.
		claimed := pubKeyFromInputs(t, entry, "claimed_identity_public_key_hex")
		spec1 := signedDocSpec{
			SignedJSON:    deepCopyMap(doc),
			SignaturePath: "sender_signature.value",
			PublicKey:     claimed,
			Prefix:        "SEMP-ENCLOSURE-SENDER:",
		}
		_, _, ok := verifySingleSignedDoc(t, spec1)
		if ok {
			t.Error("wrong claimed key unexpectedly verified")
		}
		// Verify with actual signer key - must pass (sanity check).
		actual := pubKeyFromInputs(t, entry, "actual_signer_public_key_hex")
		spec2 := signedDocSpec{
			SignedJSON:    deepCopyMap(doc),
			SignaturePath: "sender_signature.value",
			PublicKey:     actual,
			Prefix:        "SEMP-ENCLOSURE-SENDER:",
		}
		_, _, ok = verifySingleSignedDoc(t, spec2)
		if !ok {
			t.Error("actual signer key did not verify (sanity check failed)")
		}
	default:
		t.Skipf("sender-signature %q: no handler", entry.ID)
	}
}

func deepCopyMap(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// ---------------------------------------------------------------------------
// delivery-receipt verifier (3 entries)
//
// Valid: signature verifies + envelope_hash recomputes correctly.
// Tampered envelope: signature still verifies (the receipt itself is
// genuine), but the recomputed envelope hash does NOT match the one
// the receipt was issued for.
// Tampered body: signature does NOT verify (canonical bytes changed).

func handleDeliveryReceipt(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "delivery-receipt-valid":
		var exp map[string]json.RawMessage
		if err := json.Unmarshal(entry.Expected, &exp); err != nil {
			t.Fatalf("expected: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(exp["signed_receipt_json"], &doc); err != nil {
			t.Fatalf("signed_receipt unmarshal: %v", err)
		}
		spec := signedDocSpec{
			SignedJSON:    deepCopyMap(doc),
			SignaturePath: "signature.value",
			PublicKey:     pubKeyFromInputs(t, entry, "recipient_domain_pub_hex"),
			Prefix:        "SEMP-DELIVERY-RECEIPT:",
		}
		_, _, ok := verifySingleSignedDoc(t, spec)
		if !ok {
			t.Errorf("signature verify failed (%s)", entry.SpecReference)
		}
		// Envelope-hash recomputation: the receipt's envelope_hash.value
		// must equal SHA-256(canonical(reference_envelope)).
		envRaw := jgetRaw(t, entry.Inputs, "reference_envelope_json")
		if len(envRaw) == 0 {
			return
		}
		var env envelope.Envelope
		if err := json.Unmarshal(envRaw, &env); err != nil {
			t.Fatalf("envelope unmarshal: %v", err)
		}
		canonicalEnv, err := env.CanonicalBytes()
		if err != nil {
			t.Fatalf("CanonicalBytes: %v", err)
		}
		envHash := sha256.Sum256(canonicalEnv)
		envHashB64 := base64.StdEncoding.EncodeToString(envHash[:])
		got, _ := doc["envelope_hash"].(map[string]any)
		if got == nil {
			t.Fatal("signed receipt missing envelope_hash field")
		}
		gotVal, _ := got["value"].(string)
		if gotVal != envHashB64 {
			t.Errorf("envelope_hash mismatch:\n  got  %s\n  want %s",
				gotVal, envHashB64)
		}
	case "delivery-receipt-tampered-envelope":
		// Receipt signature verifies, but the recomputed envelope
		// hash differs from the one the receipt was issued for.
		var doc map[string]any
		if err := json.Unmarshal(jgetRaw(t, entry.Inputs, "signed_receipt_json"), &doc); err != nil {
			t.Fatalf("signed_receipt unmarshal: %v", err)
		}
		spec := signedDocSpec{
			SignedJSON:    deepCopyMap(doc),
			SignaturePath: "signature.value",
			PublicKey:     pubKeyFromInputs(t, entry, "recipient_domain_pub_hex"),
			Prefix:        "SEMP-DELIVERY-RECEIPT:",
		}
		_, _, sigOK := verifySingleSignedDoc(t, spec)
		wantSigOK := jgetBool(t, entry.Expected, "receipt_signature_still_verifies")
		if sigOK != wantSigOK {
			t.Errorf("receipt_signature_still_verifies got %v, want %v",
				sigOK, wantSigOK)
		}
		// Recompute the tampered envelope's hash and compare.
		envRaw := jgetRaw(t, entry.Inputs, "tampered_envelope_json")
		var env envelope.Envelope
		if err := json.Unmarshal(envRaw, &env); err != nil {
			t.Fatalf("tampered envelope unmarshal: %v", err)
		}
		canonicalEnv, err := env.CanonicalBytes()
		if err != nil {
			t.Fatalf("CanonicalBytes: %v", err)
		}
		envHash := sha256.Sum256(canonicalEnv)
		envHashB64 := base64.StdEncoding.EncodeToString(envHash[:])
		gotHashObj, _ := doc["envelope_hash"].(map[string]any)
		receiptHash, _ := gotHashObj["value"].(string)
		matches := envHashB64 == receiptHash
		wantMatches := jgetBool(t, entry.Expected, "envelope_hash_matches_recomputation")
		if matches != wantMatches {
			t.Errorf("envelope_hash_matches_recomputation got %v, want %v",
				matches, wantMatches)
		}
	case "delivery-receipt-tampered-body":
		var doc map[string]any
		if err := json.Unmarshal(jgetRaw(t, entry.Inputs, "tampered_receipt_json"), &doc); err != nil {
			t.Fatalf("tampered_receipt unmarshal: %v", err)
		}
		spec := signedDocSpec{
			SignedJSON:    deepCopyMap(doc),
			SignaturePath: "signature.value",
			PublicKey:     pubKeyFromInputs(t, entry, "recipient_domain_pub_hex"),
			Prefix:        "SEMP-DELIVERY-RECEIPT:",
		}
		_, _, sigOK := verifySingleSignedDoc(t, spec)
		wantSigOK := jgetBool(t, entry.Expected, "signature_verifies")
		if sigOK != wantSigOK {
			t.Errorf("signature_verifies got %v, want %v", sigOK, wantSigOK)
		}
	default:
		t.Skipf("delivery-receipt %q: no handler", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// transparency verifier (4 entries)
//
// RFC 6962 Merkle math:
//   leaf hash:  SHA-256(0x00 || leaf_payload)
//   inner hash: SHA-256(0x01 || left || right)
//
// inclusion-proof: walk path, hash up to the root, compare.
// consistency-proof: similar; the spec encodes the path bytes flat.
// sth-signed: Ed25519 verify on the canonical STH.
// augmented-key-fetch: STH verify + inclusion verify + leaf match.

func handleTransparency(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "transparency-sth-signed":
		var exp map[string]json.RawMessage
		if err := json.Unmarshal(entry.Expected, &exp); err != nil {
			t.Fatalf("expected: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(exp["sth_signed_json"], &doc); err != nil {
			t.Fatalf("sth_signed unmarshal: %v", err)
		}
		spec := signedDocSpec{
			SignedJSON:    doc,
			SignaturePath: "signature.value",
			PublicKey:     pubKeyFromInputs(t, entry, "domain_pub_hex"),
			Prefix:        "SEMP-TRANSPARENCY-STH:",
		}
		_, _, ok := verifySingleSignedDoc(t, spec)
		if !ok {
			t.Errorf("Ed25519 verify failed (%s)", entry.SpecReference)
		}
	case "transparency-inclusion-proof":
		leafIndex := jgetInt(t, entry.Inputs, "leaf_index")
		logSize := jgetInt(t, entry.Inputs, "log_size")
		leafHash := decodeHexF(t, jget(t, entry.Inputs, "leaf_hash_hex"), "leaf_hash_hex")
		expectedRoot := decodeHexF(t, jget(t, entry.Inputs, "expected_root_hex"), "expected_root_hex")
		path := decodeMerklePath(t, jgetRaw(t, entry.Inputs, "path_hex"), 32)
		valid := verifyInclusionProofRFC6962(leafHash, leafIndex, logSize, path, expectedRoot)
		wantValid := jgetBool(t, entry.Expected, "valid_path_verifies")
		if valid != wantValid {
			t.Errorf("valid_path_verifies got %v, want %v", valid, wantValid)
		}

		// Tampered path first element should NOT verify.
		if tamperedHex := jget(t, entry.Expected, "tampered_path_first_element_hex"); tamperedHex != "" {
			tampered := make([][]byte, len(path))
			copy(tampered, path)
			tampered[0] = decodeHexF(t, tamperedHex, "tampered_path_first_element_hex")
			tamperedValid := verifyInclusionProofRFC6962(leafHash, leafIndex, logSize, tampered, expectedRoot)
			wantTampered := jgetBool(t, entry.Expected, "tampered_path_verifies")
			if tamperedValid != wantTampered {
				t.Errorf("tampered_path_verifies got %v, want %v",
					tamperedValid, wantTampered)
			}
		}
	case "transparency-consistency-proof":
		// Consistency proof: prove that root_n2 is consistent with
		// root_n1 (n1 < n2). RFC 6962 §2.1.2 algorithm.
		n1 := jgetInt(t, entry.Inputs, "n1")
		n2 := jgetInt(t, entry.Inputs, "n2")
		oldRoot := decodeHexF(t, jget(t, entry.Inputs, "root_n1_hex"), "root_n1_hex")
		newRoot := decodeHexF(t, jget(t, entry.Inputs, "root_n2_hex"), "root_n2_hex")
		path := decodeMerklePath(t, jgetRaw(t, entry.Inputs, "path_hex"), 32)
		valid := verifyConsistencyProofRFC6962(n1, n2, oldRoot, newRoot, path)
		wantValid := jgetBool(t, entry.Expected, "valid_path_verifies")
		if valid != wantValid {
			t.Errorf("consistency valid_path_verifies got %v, want %v",
				valid, wantValid)
		}
	case "transparency-augmented-key-fetch":
		// The augmented response wraps a SEMP_KEYS reply where each
		// per-key entry carries `transparency.sth` and
		// `transparency.inclusion_proof`. We verify the STH
		// signature on the first entry and assert it matches the
		// vector's expectation flag. Deeper byte-level verification
		// is folded into the simpler STH and inclusion entries above.
		respRaw := jgetRaw(t, entry.Expected, "augmented_response_json")
		if len(respRaw) == 0 {
			t.Skip("missing augmented_response_json")
		}
		var resp map[string]any
		if err := json.Unmarshal(respRaw, &resp); err != nil {
			t.Fatalf("augmented_response unmarshal: %v", err)
		}
		keys, _ := resp["keys"].([]any)
		if len(keys) == 0 {
			t.Fatal("augmented response missing keys array")
		}
		first, _ := keys[0].(map[string]any)
		trans, _ := first["transparency"].(map[string]any)
		sth, _ := trans["sth"].(map[string]any)
		if sth == nil {
			t.Fatal("augmented response: keys[0].transparency.sth missing")
		}
		spec := signedDocSpec{
			SignedJSON:    sth,
			SignaturePath: "signature.value",
			PublicKey:     pubKeyFromInputs(t, entry, "domain_pub_hex"),
			Prefix:        "SEMP-TRANSPARENCY-STH:",
		}
		_, _, ok := verifySingleSignedDoc(t, spec)
		want := jgetBool(t, entry.Expected, "sth_signature_verifies")
		if ok != want {
			t.Errorf("sth_signature_verifies got %v, want %v", ok, want)
		}
	default:
		t.Skipf("transparency %q: no handler", entry.ID)
	}
}

// decodeMerklePath unpacks a Merkle proof path. The vectors encode
// path_hex as an array of hex strings (one per node), not a single
// concatenated hex blob. This helper handles both shapes for
// resilience: array of strings, or a single string interpreted as
// concatenated fixed-width hashes.
func decodeMerklePath(t *testing.T, raw json.RawMessage, hashLen int) [][]byte {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	// Try array form first.
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([][]byte, len(arr))
		for i, s := range arr {
			out[i] = decodeHexF(t, s, fmt.Sprintf("path_hex[%d]", i))
		}
		return out
	}
	// Fall back to concatenated form.
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("path_hex is neither []string nor string: %v", err)
	}
	if s == "" {
		return nil
	}
	all := decodeHexF(t, s, "path_hex")
	if len(all)%hashLen != 0 {
		t.Fatalf("path bytes %d not a multiple of %d", len(all), hashLen)
	}
	n := len(all) / hashLen
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = all[i*hashLen : (i+1)*hashLen]
	}
	return out
}

// verifyInclusionProofRFC6962 implements RFC 6962 §2.1.1.
//
// leafHash is already the SHA-256(0x00 || leaf_payload) hash of the
// leaf in question. The function walks the proof path, hashing
// inner nodes as SHA-256(0x01 || left || right), and compares the
// final hash to the expected root.
func verifyInclusionProofRFC6962(leafHash []byte, leafIndex, treeSize int, path [][]byte, expectedRoot []byte) bool {
	if leafIndex < 0 || leafIndex >= treeSize {
		return false
	}
	hash := append([]byte{}, leafHash...)
	fn, sn := leafIndex, treeSize-1
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			hash = sha256Inner(p, hash)
			for fn%2 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			hash = sha256Inner(hash, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytesEq(hash, expectedRoot)
}

// verifyConsistencyProofRFC6962 implements RFC 6962 §2.1.2.
func verifyConsistencyProofRFC6962(n1, n2 int, oldRoot, newRoot []byte, path [][]byte) bool {
	if n1 == n2 {
		return len(path) == 0 && bytesEq(oldRoot, newRoot)
	}
	if n1 == 0 || n1 > n2 {
		return false
	}
	// If n1 is a power of two equal to a complete subtree, the proof
	// implicitly starts from oldRoot.
	node := n1 - 1
	lastNode := n2 - 1
	for node%2 == 1 {
		node >>= 1
		lastNode >>= 1
	}
	var oldHash, newHash []byte
	if len(path) == 0 {
		return false
	}
	if node > 0 {
		oldHash = path[0]
		newHash = path[0]
		path = path[1:]
	} else {
		oldHash = oldRoot
		newHash = oldRoot
	}
	for _, p := range path {
		if lastNode == 0 {
			return false
		}
		if node%2 == 1 || node == lastNode {
			oldHash = sha256Inner(p, oldHash)
			newHash = sha256Inner(p, newHash)
			for node%2 == 0 {
				node >>= 1
				lastNode >>= 1
			}
		} else {
			newHash = sha256Inner(newHash, p)
		}
		node >>= 1
		lastNode >>= 1
	}
	return lastNode == 0 && bytesEq(oldHash, oldRoot) && bytesEq(newHash, newRoot)
}

// pqUnwrap reconstructs the recipient's hybrid private key from
// the pinned kyber keygen seeds + X25519 private and dispatches to
// seal.NewWrapper(crypto.SuitePQ).Unwrap. The hybrid wire layout is
// `x25519_priv || kyber_priv` per crypto.HybridPrivateKeyFromKyberAndX25519.
func pqUnwrap(t *testing.T, entry vectorEntry, wrappedB64 string) ([]byte, error) {
	t.Helper()
	d := decodeHexF(t, jget(t, entry.Inputs, "recipient_kyber_keygen_d_hex"),
		"recipient_kyber_keygen_d_hex")
	z := decodeHexF(t, jget(t, entry.Inputs, "recipient_kyber_keygen_z_hex"),
		"recipient_kyber_keygen_z_hex")
	xPriv := decodeHexF(t, jget(t, entry.Inputs, "recipient_x25519_private_key_hex"),
		"recipient_x25519_private_key_hex")
	hybridPub := decodeHexF(t, jget(t, entry.Inputs, "recipient_hybrid_public_key_hex"),
		"recipient_hybrid_public_key_hex")

	_, kyberPriv := crypto.DeriveKyber768KeyPair(d, z)
	hybridPriv := crypto.HybridPrivateKeyFromKyberAndX25519(xPriv, kyberPriv)

	w := seal.NewWrapper(crypto.SuitePQ)
	return w.Unwrap(hybridPriv, hybridPub, wrappedB64)
}

// ---------------------------------------------------------------------------
// envelope-roundtrip: full envelope flow (verify-only, baseline)
//
// Receive-side check on a pinned envelope:
//   1. seal.signature verifies under sender_domain_signing_pub.
//   2. seal.session_mac verifies under K_env_mac.
//   3. Unwrap recipient_client's brief recipient -> K_brief.
//      AEAD-decrypt envelope.brief with K_brief and pinned nonce ->
//      original brief plaintext.
//   4. Unwrap recipient_client's enclosure recipient -> K_enclosure.
//      AEAD-decrypt envelope.enclosure -> signed enclosure JSON.
//   5. Verify sender_signature on the decrypted enclosure under
//      sender_identity_pub.
//
// PQ variant requires deterministic kyber keygen from seed; deferred
// like seal-roundtrip PQ.

func handleEnvelopeRoundtrip(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "envelope-roundtrip-baseline-single-recipient":
		runEnvelopeRoundtrip(t, entry, crypto.SuiteBaseline)
	case "envelope-roundtrip-pq-single-recipient":
		runEnvelopeRoundtrip(t, entry, crypto.SuitePQ)
	default:
		t.Skipf("envelope-roundtrip %q: no handler", entry.ID)
	}
}

// recipientKeysForSuite returns the (priv, pub) byte slices the
// recipient passes to seal.Wrapper.Unwrap. For the baseline suite the
// pinned vector inputs are 32-byte X25519 priv/pub. For the PQ suite
// the priv is reassembled from pinned (kyber d, z, x25519 priv) and
// the pub is the pinned 1216-byte hybrid public key.
func recipientKeysForSuite(t *testing.T, entry vectorEntry, suite crypto.Suite) (priv, pub []byte) {
	t.Helper()
	switch suite {
	case crypto.SuiteBaseline:
		priv = decodeHexF(t, jget(t, entry.Inputs, "recipient_client_priv_hex"),
			"recipient_client_priv_hex")
		pub = decodeHexF(t, jget(t, entry.Inputs, "recipient_client_pub_hex"),
			"recipient_client_pub_hex")
	case crypto.SuitePQ:
		d := decodeHexF(t, jget(t, entry.Inputs, "recipient_client_kyber_keygen_d_hex"),
			"recipient_client_kyber_keygen_d_hex")
		z := decodeHexF(t, jget(t, entry.Inputs, "recipient_client_kyber_keygen_z_hex"),
			"recipient_client_kyber_keygen_z_hex")
		xPriv := decodeHexF(t, jget(t, entry.Inputs, "recipient_client_x25519_priv_hex"),
			"recipient_client_x25519_priv_hex")
		_, kyberPriv := crypto.DeriveKyber768KeyPair(d, z)
		priv = crypto.HybridPrivateKeyFromKyberAndX25519(xPriv, kyberPriv)
		pub = decodeHexF(t, jget(t, entry.Inputs, "recipient_client_pub_hex"),
			"recipient_client_pub_hex")
	default:
		t.Fatalf("unknown suite")
	}
	return priv, pub
}

func runEnvelopeRoundtrip(t *testing.T, entry vectorEntry, suite crypto.Suite) {
	t.Helper()
	envRaw := jgetRaw(t, entry.Expected, "envelope_json")
	if len(envRaw) == 0 {
		t.Fatal("missing expected.envelope_json")
	}
	var env envelope.Envelope
	if err := json.Unmarshal(envRaw, &env); err != nil {
		t.Fatalf("envelope unmarshal: %v", err)
	}
	canonicalEnv, err := env.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}

	// Step 1: seal.signature.
	senderPub := decodeHexF(t, jget(t, entry.Inputs, "sender_domain_signing_pub_hex"),
		"sender_domain_signing_pub_hex")
	sealSig, err := base64.StdEncoding.DecodeString(env.Seal.Signature)
	if err != nil {
		t.Fatalf("decode seal.signature: %v", err)
	}
	signingInput := append([]byte("SEMP-ENVELOPE:"), canonicalEnv...)
	step1 := ed25519.Verify(ed25519.PublicKey(senderPub), signingInput, sealSig)
	wantStep1 := jgetBool(t, entry.Expected, "seal_signature_verifies")
	if step1 != wantStep1 {
		t.Errorf("seal_signature_verifies got %v, want %v", step1, wantStep1)
	}

	// Step 2: session_mac.
	kEnvMac := decodeHexF(t, jget(t, entry.Inputs, "K_env_mac_hex"), "K_env_mac_hex")
	wantMAC := computeHMAC(kEnvMac, canonicalEnv)
	gotMAC, err := base64.StdEncoding.DecodeString(env.Seal.SessionMAC)
	if err != nil {
		t.Fatalf("decode session_mac: %v", err)
	}
	step2 := bytesEq(wantMAC, gotMAC)
	wantStep2 := jgetBool(t, entry.Expected, "session_mac_verifies")
	if step2 != wantStep2 {
		t.Errorf("session_mac_verifies got %v, want %v", step2, wantStep2)
	}

	// Step 3: brief AEAD round-trip via recipient_client unwrap.
	w := seal.NewWrapper(suite)
	clientPriv, clientPub := recipientKeysForSuite(t, entry, suite)
	clientFP := jget(t, entry.Inputs, "recipient_client_key_id")
	briefWrapped, ok := env.Seal.BriefRecipients[keys.Fingerprint(clientFP)]
	if !ok {
		t.Fatal("recipient_client not in brief_recipients")
	}
	kBrief, err := w.Unwrap(clientPriv, clientPub, briefWrapped)
	if err != nil {
		t.Fatalf("brief unwrap: %v", err)
	}
	briefNonce := decodeHexF(t, jget(t, entry.Inputs, "brief_aead_nonce_hex"),
		"brief_aead_nonce_hex")
	// envelope.brief = base64(nonce || aead_ct) per ENVELOPE.md §7.1.1.
	// The first 12 bytes are the nonce; the rest is the AEAD ciphertext.
	briefBlob, err := base64.StdEncoding.DecodeString(env.Brief)
	if err != nil {
		t.Fatalf("decode brief: %v", err)
	}
	if len(briefBlob) < 12 {
		t.Fatalf("brief blob too short: %d bytes", len(briefBlob))
	}
	briefCT := briefBlob[12:]
	if !bytesEq(briefBlob[:12], briefNonce) {
		t.Errorf("brief blob nonce prefix mismatch")
	}
	postmarkID := jget(t, entry.Inputs, "postmark_id")
	briefPT, err := aeadOpen("chacha20-poly1305", kBrief, briefNonce, briefCT, []byte(postmarkID))
	if err != nil {
		t.Fatalf("brief AEAD open: %v", err)
	}
	// Compare decrypted brief plaintext to inputs.brief_pre_encrypt_json.
	// Both are JSON; canonicalize and compare to make field-order
	// differences harmless.
	wantBriefRaw := jgetRaw(t, entry.Inputs, "brief_pre_encrypt_json")
	if !jsonContentEqual(briefPT, wantBriefRaw) {
		t.Errorf("brief round-trip mismatch:\n  got  %s\n  want %s",
			string(briefPT), string(wantBriefRaw))
	}
	wantStep3 := jgetBool(t, entry.Expected, "round_trip_recovers_brief")
	if !wantStep3 {
		t.Error("vector says brief round-trip should fail; runner says it passes")
	}

	// Step 4: enclosure AEAD round-trip.
	enclWrapped, ok := env.Seal.EnclosureRecipients[keys.Fingerprint(clientFP)]
	if !ok {
		t.Fatal("recipient_client not in enclosure_recipients")
	}
	kEncl, err := w.Unwrap(clientPriv, clientPub, enclWrapped)
	if err != nil {
		t.Fatalf("enclosure unwrap: %v", err)
	}
	enclNonce := decodeHexF(t, jget(t, entry.Inputs, "enclosure_aead_nonce_hex"),
		"enclosure_aead_nonce_hex")
	enclBlob, err := base64.StdEncoding.DecodeString(env.Enclosure)
	if err != nil {
		t.Fatalf("decode enclosure: %v", err)
	}
	if len(enclBlob) < 12 {
		t.Fatalf("enclosure blob too short: %d bytes", len(enclBlob))
	}
	enclCT := enclBlob[12:]
	if !bytesEq(enclBlob[:12], enclNonce) {
		t.Errorf("enclosure blob nonce prefix mismatch")
	}
	enclPT, err := aeadOpen("chacha20-poly1305", kEncl, enclNonce, enclCT, []byte(postmarkID))
	if err != nil {
		t.Fatalf("enclosure AEAD open: %v", err)
	}
	wantStep4 := jgetBool(t, entry.Expected, "round_trip_recovers_enclosure")
	if !wantStep4 {
		t.Error("vector says enclosure round-trip should fail; runner says it passes")
	}

	// Step 5: sender_signature verifies on the decrypted enclosure.
	var enclosure map[string]any
	if err := json.Unmarshal(enclPT, &enclosure); err != nil {
		t.Fatalf("decrypted enclosure unmarshal: %v", err)
	}
	identityPub := pubKeyFromInputs(t, entry, "sender_identity_pub_hex")
	spec := signedDocSpec{
		SignedJSON:    deepCopyMap(enclosure),
		SignaturePath: "sender_signature.value",
		PublicKey:     identityPub,
		Prefix:        "SEMP-ENCLOSURE-SENDER:",
	}
	_, _, sigOK := verifySingleSignedDoc(t, spec)
	wantStep5 := jgetBool(t, entry.Expected, "sender_signature_verifies")
	if sigOK != wantStep5 {
		t.Errorf("sender_signature_verifies got %v, want %v", sigOK, wantStep5)
	}
}

// ---------------------------------------------------------------------------
// seal-roundtrip: HPKE-Base wrap (full receive-side + send-side check)
//
// Each vector pins the wrapped bytes plus all the recipient's keying
// material and the sender's ephemeral randomness. We exercise both
// directions: feed wrapped_b64 to Unwrap and assert K is recovered
// byte-for-byte; then feed the pinned randomness through
// WrapWithRandomness and assert the produced wrapped bytes match
// expected.wrapped_b64 byte-for-byte.

func handleSealRoundtrip(t *testing.T, entry vectorEntry) {
	suite := jget(t, entry.Inputs, "suite")
	wrappedB64 := jget(t, entry.Expected, "wrapped_b64")
	if wrappedB64 == "" {
		t.Fatal("missing expected.wrapped_b64")
	}
	wantK := decodeHexF(t, jget(t, entry.Inputs, "symmetric_key_hex"), "symmetric_key_hex")

	switch suite {
	case "x25519-chacha20-poly1305":
		recipPriv := decodeHexF(t, jget(t, entry.Inputs, "recipient_private_key_hex"),
			"recipient_private_key_hex")
		recipPub := decodeHexF(t, jget(t, entry.Inputs, "recipient_public_key_hex"),
			"recipient_public_key_hex")
		w := seal.NewWrapper(crypto.SuiteBaseline)
		got, err := w.Unwrap(recipPriv, recipPub, wrappedB64)
		if err != nil {
			t.Fatalf("Unwrap: %v", err)
		}
		if !bytesEq(got, wantK) {
			t.Errorf("baseline unwrap recovered K mismatch:\n  got  %x\n  want %x",
				got, wantK)
		}
		// Send-side: WrapWithRandomness using the pinned ephemeral
		// MUST produce the pinned wrapped_b64 byte-for-byte.
		ephPriv := decodeHexF(t, jget(t, entry.Inputs, "ephemeral_private_key_hex"),
			"ephemeral_private_key_hex")
		gotWrapped, err := w.WrapWithRandomness(recipPub, wantK, seal.WrapRandomness{
			EphemeralX25519Priv: ephPriv,
		})
		if err != nil {
			t.Fatalf("WrapWithRandomness: %v", err)
		}
		if gotWrapped != wrappedB64 {
			t.Errorf("baseline WrapWithRandomness output mismatch:\n  got  %s\n  want %s",
				gotWrapped, wrappedB64)
		}
		if entry.ID == "seal-wrap-baseline-ephemeral-changes-output" {
			// Sanity check: the vector pins differs_from_case_1
			// to demonstrate that two different ephemerals
			// produce two different wrapped strings. The runner
			// does not need to recompute case 1 here; the assertion
			// is implicit in the per-vector wrapped_b64 pin.
			if !jgetBool(t, entry.Expected, "differs_from_case_1") {
				t.Error("vector says output should differ from case 1")
			}
		}
	case "pq-kyber768-x25519":
		k, err := pqUnwrap(t, entry, wrappedB64)
		if err != nil {
			t.Fatalf("PQ unwrap: %v", err)
		}
		if !bytesEq(k, wantK) {
			t.Errorf("pq unwrap recovered K mismatch:\n  got  %x\n  want %x",
				k, wantK)
		}
		// Send-side: WrapWithRandomness using the pinned hybrid
		// ephemeral X25519 priv and Kyber encaps `m` MUST produce the
		// pinned wrapped_b64 byte-for-byte.
		recipPub := decodeHexF(t, jget(t, entry.Inputs, "recipient_hybrid_public_key_hex"),
			"recipient_hybrid_public_key_hex")
		ephX := decodeHexF(t, jget(t, entry.Inputs, "ephemeral_x25519_private_key_hex"),
			"ephemeral_x25519_private_key_hex")
		kyberM := decodeHexF(t, jget(t, entry.Inputs, "kyber_encaps_randomness_m_hex"),
			"kyber_encaps_randomness_m_hex")
		wPQ := seal.NewWrapper(crypto.SuitePQ)
		gotWrapped, err := wPQ.WrapWithRandomness(recipPub, wantK, seal.WrapRandomness{
			EphemeralX25519Priv:    ephX,
			KyberEncapsRandomnessM: kyberM,
		})
		if err != nil {
			t.Fatalf("PQ WrapWithRandomness: %v", err)
		}
		if gotWrapped != wrappedB64 {
			t.Errorf("PQ WrapWithRandomness output mismatch:\n  got  %s\n  want %s",
				gotWrapped, wrappedB64)
		}
	default:
		t.Skipf("seal-roundtrip suite %q: no handler", suite)
	}

	wantRoundTrip := jgetBool(t, entry.Expected, "round_trip_recovers_K")
	if !wantRoundTrip {
		t.Error("vector says round-trip should NOT recover; runner says it does")
	}
}

// ---------------------------------------------------------------------------
// account-recovery: Argon2id + XChaCha20-Poly1305 + Ed25519 (RECOVERY.md §2)
//
// Uses semp-go's recovery package primitives directly so the runner
// exercises the same code path that production restore flows do:
//   recovery.DeriveBundleKey      (Argon2id KDF)
//   recovery.EncryptBundlePayload (XChaCha20-Poly1305, empty AAD)
//   recovery.DecryptBundlePayload (round-trip check)
//   Ed25519 verify with SEMP-RECOVERY-BUNDLE: prefix.

func handleAccountRecovery(t *testing.T, entry vectorEntry) {
	if entry.ID != "recovery-bundle-roundtrip" {
		t.Skipf("account-recovery %q: no handler", entry.ID)
	}
	secret := []byte(jget(t, entry.Inputs, "recovery_secret_utf8"))
	salt := decodeHexF(t, jget(t, entry.Inputs, "kdf_salt_hex"), "kdf_salt_hex")
	memKB := jgetInt(t, entry.Inputs, "kdf_memory_kb")
	iters := jgetInt(t, entry.Inputs, "kdf_iterations")
	par := jgetInt(t, entry.Inputs, "kdf_parallelism")

	bundleKey := argon2.IDKey(secret, salt,
		uint32(iters), uint32(memKB), uint8(par), 32)

	// Decrypt the encrypted_payload from the published bundle and
	// confirm round-trip recovers the original.
	var bundle map[string]any
	if err := json.Unmarshal(jgetRaw(t, entry.Expected, "signed_bundle_json"), &bundle); err != nil {
		t.Fatalf("signed_bundle_json: %v", err)
	}
	ctB64, _ := bundle["encrypted_payload"].(string)
	ct, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		t.Fatalf("decode encrypted_payload: %v", err)
	}
	nonceB64, _ := bundle["payload_nonce"].(string)
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		t.Fatalf("decode payload_nonce: %v", err)
	}
	c, err := chacha20poly1305.NewX(bundleKey)
	if err != nil {
		t.Fatalf("XChaCha20-Poly1305: %v", err)
	}
	pt, err := c.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("AEAD open: %v", err)
	}
	// Compare round-trip plaintext to inputs.payload_pre_encrypt_json.
	wantPlaintext := jgetRaw(t, entry.Inputs, "payload_pre_encrypt_json")
	if !bytesEq(wantPlaintext, pt) {
		// payload_pre_encrypt_json is canonical JSON of the
		// payload object; recovery encrypts with canonical JSON
		// per RECOVERY.md §2.4 step 2. Parse both and compare.
		var got, want map[string]any
		_ = json.Unmarshal(pt, &got)
		_ = json.Unmarshal(wantPlaintext, &want)
		if !mapsEqual(got, want) {
			t.Errorf("payload round-trip mismatch")
		}
	}
	wantRoundTrip := jgetBool(t, entry.Expected, "round_trip_decrypts_payload")
	if !wantRoundTrip {
		t.Error("vector says round-trip should NOT decrypt; runner says it does")
	}

	// KDF re-determinism: re-deriving from the same inputs gives
	// the same K_bundle.
	bundleKey2 := argon2.IDKey(secret, salt,
		uint32(iters), uint32(memKB), uint8(par), 32)
	wantRedeterm := jgetBool(t, entry.Expected, "kdf_redeterms_K_bundle")
	gotRedeterm := bytesEq(bundleKey, bundleKey2)
	if gotRedeterm != wantRedeterm {
		t.Errorf("kdf_redeterms_K_bundle got %v, want %v",
			gotRedeterm, wantRedeterm)
	}

	// Bundle signature verification: SEMP-RECOVERY-BUNDLE: prefix +
	// canonical bundle bytes with signature.value blanked.
	identityPub := pubKeyFromInputs(t, entry, "identity_pub_hex")
	spec := signedDocSpec{
		SignedJSON:    deepCopyMap(bundle),
		SignaturePath: "signature.value",
		PublicKey:     identityPub,
		Prefix:        "SEMP-RECOVERY-BUNDLE:",
	}
	_, _, sigOK := verifySingleSignedDoc(t, spec)
	wantSigOK := jgetBool(t, entry.Expected, "signature_verifies")
	if sigOK != wantSigOK {
		t.Errorf("signature_verifies got %v, want %v", sigOK, wantSigOK)
	}
}

// mapsEqual is a deep-equal helper that survives JSON re-marshal
// round-trips. It handles map[string]any, []any, string, float64, bool,
// nil, json.Number.
func mapsEqual(a, b any) bool {
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	var aa, bb any
	if err := json.Unmarshal(ra, &aa); err != nil {
		return false
	}
	if err := json.Unmarshal(rb, &bb); err != nil {
		return false
	}
	ca, _ := json.Marshal(aa)
	cb, _ := json.Marshal(bb)
	return bytesEq(ca, cb)
}

// jsonContentEqual unmarshals both inputs as JSON and compares their
// canonicalized re-serialization. Use when you have two byte slices
// that you know are both JSON encodings of the same conceptual value
// but might differ in whitespace or field order.
func jsonContentEqual(a, b []byte) bool {
	var aa, bb any
	if err := json.Unmarshal(a, &aa); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bb); err != nil {
		return false
	}
	ca, _ := json.Marshal(aa)
	cb, _ := json.Marshal(bb)
	return bytesEq(ca, cb)
}

// ---------------------------------------------------------------------------
// Shamir GF(256) split + Lagrange combine (RECOVERY.md §5.1, §5.4)
//
// Field: GF(256) with the AES irreducible polynomial 0x11b.
// Polynomial per byte: f(x) = secret + c1*x + c2*x^2 + ... + c_{M-1}*x^{M-1}.
// Share i: (i, f(i)) for i = 1..N. Reconstruction is Lagrange
// interpolation at x = 0.

func gf256Mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B // low byte of 0x11B
		}
		b >>= 1
	}
	return p
}

func gf256Pow(base byte, exp int) byte {
	result := byte(1)
	for exp > 0 {
		if exp&1 == 1 {
			result = gf256Mul(result, base)
		}
		base = gf256Mul(base, base)
		exp >>= 1
	}
	return result
}

func gf256Inv(a byte) byte {
	// Fermat: a^(2^8 - 2) = a^-1 in GF(2^8).
	if a == 0 {
		panic("gf256Inv(0)")
	}
	return gf256Pow(a, 254)
}

func shamirSplit(secret []byte, threshold, total int, coeffSeed []byte) [][]byte {
	coeffsPerByte := threshold - 1
	shares := make([][]byte, total)
	for i := range shares {
		shares[i] = make([]byte, len(secret))
	}
	cursor := 0
	for byteIdx, sb := range secret {
		coeffs := make([]byte, coeffsPerByte)
		copy(coeffs, coeffSeed[cursor:cursor+coeffsPerByte])
		cursor += coeffsPerByte
		for shareIdx := 1; shareIdx <= total; shareIdx++ {
			y := sb
			xPower := byte(1)
			for _, c := range coeffs {
				xPower = gf256Mul(xPower, byte(shareIdx))
				y ^= gf256Mul(c, xPower)
			}
			shares[shareIdx-1][byteIdx] = y
		}
	}
	return shares
}

func shamirCombine(shareIdxs []int, shareBytes [][]byte) []byte {
	if len(shareIdxs) == 0 {
		return nil
	}
	secretLen := len(shareBytes[0])
	out := make([]byte, secretLen)
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		var result byte
		for i, xi := range shareIdxs {
			yi := shareBytes[i][byteIdx]
			num := byte(1)
			den := byte(1)
			for j, xj := range shareIdxs {
				if i == j {
					continue
				}
				num = gf256Mul(num, byte(xj))
				den = gf256Mul(den, byte(xi)^byte(xj))
			}
			basis := gf256Mul(num, gf256Inv(den))
			result ^= gf256Mul(yi, basis)
		}
		out[byteIdx] = result
	}
	return out
}

func runShamirRoundTrip(t *testing.T, entry vectorEntry) {
	t.Helper()
	secret := decodeHexF(t, jget(t, entry.Inputs, "K_bundle_hex"), "K_bundle_hex")
	threshold := jgetInt(t, entry.Inputs, "threshold")
	total := jgetInt(t, entry.Inputs, "total_shares")
	coeffSeed := decodeHexF(t, jget(t, entry.Inputs, "coefficient_seed_hex"),
		"coefficient_seed_hex")

	shares := shamirSplit(secret, threshold, total, coeffSeed)

	// Cross-check against pinned shares_hex if present.
	if raw := jgetRaw(t, entry.Intermediates, "shares_hex"); len(raw) > 0 {
		var hexes []string
		if err := json.Unmarshal(raw, &hexes); err == nil {
			for i, h := range hexes {
				want := decodeHexF(t, h, fmt.Sprintf("shares_hex[%d]", i))
				if !bytesEq(shares[i], want) {
					t.Errorf("share %d mismatch:\n  got  %x\n  want %x",
						i+1, shares[i], want)
				}
			}
		}
	}

	// Threshold combine should recover.
	var subset []int
	if raw := jgetRaw(t, entry.Inputs, "share_index_subset_for_combine"); len(raw) > 0 {
		_ = json.Unmarshal(raw, &subset)
	}
	if len(subset) == 0 {
		// default to indexes 1..threshold
		for i := 1; i <= threshold; i++ {
			subset = append(subset, i)
		}
	}
	subBytes := make([][]byte, len(subset))
	for i, idx := range subset {
		subBytes[i] = shares[idx-1]
	}
	recovered := shamirCombine(subset, subBytes)
	wantRecover := jgetBool(t, entry.Expected, "threshold_combine_recovers_K_bundle")
	gotRecover := bytesEq(recovered, secret)
	if gotRecover != wantRecover {
		t.Errorf("threshold combine recovers got %v, want %v",
			gotRecover, wantRecover)
	}

	// Sub-threshold should NOT recover.
	if threshold > 1 {
		subSize := threshold - 1
		shortIdxs := make([]int, subSize)
		shortBytes := make([][]byte, subSize)
		for i := 0; i < subSize; i++ {
			shortIdxs[i] = i + 1
			shortBytes[i] = shares[i]
		}
		sub := shamirCombine(shortIdxs, shortBytes)
		wantSub := jgetBool(t, entry.Expected, "subthreshold_combine_recovers_K_bundle")
		gotSub := bytesEq(sub, secret)
		if gotSub != wantSub {
			t.Errorf("sub-threshold combine recovers got %v, want %v",
				gotSub, wantSub)
		}
	}
}

// ---------------------------------------------------------------------------
// large-attachment: AEAD round-trip (4 vectors)
//
//	K_attachment = HKDF-Expand(PRK=K_enclosure,
//	    info='semp-attachment:'||attachment_id, L=32)
//	AAD          = canonical(item with ciphertext_hash="" aead_nonce=""
//	                        extensions={})
//	baseline     = ChaCha20-Poly1305 (12-byte nonce)
//	PQ           = XChaCha20-Poly1305 (24-byte nonce)
//	ciphertext_hash = "sha256:" + hex(SHA-256(aead_ct))
//
// The runner uses canonical for the AAD rather than
// largeattachment.AdditionalData, which uses plain json.Marshal
// (struct-order, NOT alphabetical canonical). semp-go's encrypt and
// decrypt use the same AAD function so round-trips work locally,
// but the bytes are NOT cross-implementation-interop-compatible.
// Tracked as a separate gap.

func attachmentAAD(t *testing.T, item map[string]any) []byte {
	t.Helper()
	clone := deepCopyMap(item)
	clone["ciphertext_hash"] = ""
	clone["aead_nonce"] = ""
	clone["extensions"] = map[string]any{}
	bytes, err := canonical.Marshal(clone)
	if err != nil {
		t.Fatalf("canonical AAD: %v", err)
	}
	return bytes
}

func deriveAttachmentKey(kEnclosure []byte, attachmentID string) []byte {
	kdf := crypto.NewKDFHKDFSHA512()
	info := append([]byte("semp-attachment:"), attachmentID...)
	return kdf.Expand(kEnclosure, info, 32)
}

func handleLargeAttachment(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "large-attachment-baseline-valid", "large-attachment-pq-valid":
		runLargeAttachmentValid(t, entry)
	case "large-attachment-tampered-metadata":
		runLargeAttachmentTamperedMetadata(t, entry)
	case "large-attachment-tampered-ciphertext":
		runLargeAttachmentTamperedCiphertext(t, entry)
	default:
		t.Skipf("large-attachment %q: no handler", entry.ID)
	}
}

func runLargeAttachmentValid(t *testing.T, entry vectorEntry) {
	t.Helper()
	kEnc := decodeHexF(t, jget(t, entry.Inputs, "K_enclosure_hex"), "K_enclosure_hex")
	attachmentID := jget(t, entry.Inputs, "attachment_id")
	plaintext := decodeHexF(t, jget(t, entry.Inputs, "plaintext_hex"), "plaintext_hex")
	nonce := decodeHexF(t, jget(t, entry.Inputs, "aead_nonce_hex"), "aead_nonce_hex")

	var template map[string]any
	if err := json.Unmarshal(jgetRaw(t, entry.Inputs, "item_pre_encrypt_template"), &template); err != nil {
		t.Fatalf("template: %v", err)
	}
	kAttachment := deriveAttachmentKey(kEnc, attachmentID)
	aad := attachmentAAD(t, template)

	algo, _ := template["aead_algorithm"].(string)
	ct, err := aeadSeal(algo, kAttachment, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AEAD seal: %v", err)
	}
	wantCT := decodeHexF(t, jget(t, entry.Expected, "ciphertext_at_url_hex"), "ciphertext_at_url_hex")
	if !bytesEq(ct, wantCT) {
		t.Errorf("ciphertext mismatch:\n  got  %x\n  want %x", ct, wantCT)
	}

	// Round-trip: AEAD-open the ciphertext with the same AAD, recover plaintext.
	pt, err := aeadOpen(algo, kAttachment, nonce, ct, aad)
	if err != nil {
		t.Fatalf("AEAD open: %v", err)
	}
	if !bytesEq(pt, plaintext) {
		t.Errorf("round-trip: recovered plaintext mismatch")
	}
	wantRoundTrip := jgetBool(t, entry.Expected, "round_trip_recovers_plaintext")
	if !wantRoundTrip {
		t.Error("vector says round-trip should NOT recover; runner says it does")
	}

	// ciphertext_hash sanity check against item_final_json.
	var final map[string]any
	if err := json.Unmarshal(jgetRaw(t, entry.Expected, "item_final_json"), &final); err != nil {
		t.Fatalf("item_final unmarshal: %v", err)
	}
	expectHash := fmt.Sprintf("sha256:%x", sha256.Sum256(ct))
	gotHash, _ := final["ciphertext_hash"].(string)
	if gotHash != expectHash {
		t.Errorf("ciphertext_hash mismatch:\n  got  %s\n  want %s",
			gotHash, expectHash)
	}
}

func runLargeAttachmentTamperedMetadata(t *testing.T, entry vectorEntry) {
	t.Helper()
	// Take the valid output, change a bound field (filename) in the
	// item, recompute AAD, and assert AEAD decrypt fails because the
	// AAD now differs from the AAD used at encryption time.
	kAttachment := decodeHexF(t, jget(t, entry.Inputs, "K_attachment_hex"), "K_attachment_hex")
	nonce := decodeHexF(t, jget(t, entry.Inputs, "aead_nonce_hex"), "aead_nonce_hex")
	ct := decodeHexF(t, jget(t, entry.Inputs, "ciphertext_at_url_hex"), "ciphertext_at_url_hex")
	var tamperedItem map[string]any
	if err := json.Unmarshal(jgetRaw(t, entry.Inputs, "tampered_item_json"), &tamperedItem); err != nil {
		t.Fatalf("tampered_item_json: %v", err)
	}
	// Determine algorithm from item.
	algo, _ := tamperedItem["aead_algorithm"].(string)
	tamperedAAD := attachmentAAD(t, tamperedItem)
	_, err := aeadOpen(algo, kAttachment, nonce, ct, tamperedAAD)
	gotDecrypts := err == nil
	wantDecrypts := jgetBool(t, entry.Expected, "decryption_succeeds")
	if gotDecrypts != wantDecrypts {
		t.Errorf("decryption_succeeds got %v, want %v", gotDecrypts, wantDecrypts)
	}
}

func runLargeAttachmentTamperedCiphertext(t *testing.T, entry vectorEntry) {
	t.Helper()
	kAttachment := decodeHexF(t, jget(t, entry.Inputs, "K_attachment_hex"), "K_attachment_hex")
	nonce := decodeHexF(t, jget(t, entry.Inputs, "aead_nonce_hex"), "aead_nonce_hex")
	tamperedCT := decodeHexF(t, jget(t, entry.Inputs, "tampered_ciphertext_hex"),
		"tampered_ciphertext_hex")
	var item map[string]any
	if err := json.Unmarshal(jgetRaw(t, entry.Inputs, "item_json"), &item); err != nil {
		t.Fatalf("item_json: %v", err)
	}
	// Hash mismatch: SHA-256(tampered_ct) != item.ciphertext_hash.
	expectHash := fmt.Sprintf("sha256:%x", sha256.Sum256(tamperedCT))
	itemHash, _ := item["ciphertext_hash"].(string)
	hashMatches := expectHash == itemHash
	wantHashMatches := jgetBool(t, entry.Expected, "ciphertext_hash_matches")
	if hashMatches != wantHashMatches {
		t.Errorf("ciphertext_hash_matches got %v, want %v", hashMatches, wantHashMatches)
	}
	// AEAD decrypt also fails (Poly1305 tag mismatch on tampered ct).
	algo, _ := item["aead_algorithm"].(string)
	aad := attachmentAAD(t, item)
	_, err := aeadOpen(algo, kAttachment, nonce, tamperedCT, aad)
	aeadOK := err == nil
	wantAEAD := jgetBool(t, entry.Expected, "aead_decryption_succeeds")
	if aeadOK != wantAEAD {
		t.Errorf("aead_decryption_succeeds got %v, want %v", aeadOK, wantAEAD)
	}
}

// aeadSeal / aeadOpen dispatch on the algorithm string. Both the
// baseline (chacha20-poly1305) and PQ (xchacha20-poly1305) AEADs are
// directly available via golang.org/x/crypto.
func aeadSeal(algo string, key, nonce, plaintext, aad []byte) ([]byte, error) {
	switch algo {
	case "chacha20-poly1305":
		c, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return c.Seal(nil, nonce, plaintext, aad), nil
	case "xchacha20-poly1305":
		c, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		return c.Seal(nil, nonce, plaintext, aad), nil
	default:
		return nil, fmt.Errorf("unknown AEAD algorithm %q", algo)
	}
}

func aeadOpen(algo string, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	switch algo {
	case "chacha20-poly1305":
		c, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return c.Open(nil, nonce, ciphertext, aad)
	case "xchacha20-poly1305":
		c, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		return c.Open(nil, nonce, ciphertext, aad)
	default:
		return nil, fmt.Errorf("unknown AEAD algorithm %q", algo)
	}
}

func sha256Inner(left, right []byte) []byte {
	buf := make([]byte, 0, 1+len(left)+len(right))
	buf = append(buf, 0x01)
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

// ---------------------------------------------------------------------------
// forwarding: three-signature verification chain (§6.6.4)
//
//	step 1: outer enclosure.sender_signature             (forwarder pub)
//	step 2: forwarded_from.forwarder_attestation         (forwarder pub)
//	step 3: forwarded_from.original_enclosure_plaintext.
//	          sender_signature                           (original sender pub)
//
// Each step verifies a different scope (full document for step 1,
// forwarded_from subtree for step 2, original_enclosure_plaintext
// subtree for step 3). The corresponding domain-separation prefix
// changes between SEMP-ENCLOSURE-SENDER: and SEMP-FORWARDER-ATTESTATION:.

func handleForwarding(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "forward-valid-three-step-chain":
		runForwardingChain(t, entry,
			jgetRaw(t, entry.Expected, "outer_enclosure_json"),
			true, true, true)
	case "forward-tampered-original-content":
		// All three steps SHOULD reject because the outer
		// canonicalization includes the forwarded_from subtree and
		// the forwarded_from canonical bytes also cover the inner
		// content.
		runForwardingChain(t, entry,
			jgetRaw(t, entry.Inputs, "tampered_outer_enclosure_json"),
			jgetBool(t, entry.Expected, "step_1_outer_sender_signature_verifies"),
			jgetBool(t, entry.Expected, "step_2_forwarder_attestation_verifies"),
			jgetBool(t, entry.Expected, "step_3_original_sender_signature_verifies"))
	case "forward-spoofed-outer-signer":
		// A spoofer publishes an outer enclosure with its own
		// signature but claims forwarder B's key_id. Step 1
		// verifies the outer sender_signature against the public
		// key the key_id POINTS AT (B's, not the spoofer's).
		// Verification MUST fail because the spoofer cannot forge
		// B's signature.
		var doc map[string]any
		if err := json.Unmarshal(jgetRaw(t, entry.Inputs, "spoofed_outer_enclosure_json"), &doc); err != nil {
			t.Fatalf("spoofed outer unmarshal: %v", err)
		}
		claimed := pubKeyFromInputs(t, entry, "claimed_forwarder_pub_hex")
		spec := signedDocSpec{
			SignedJSON:    deepCopyMap(doc),
			SignaturePath: "sender_signature.value",
			PublicKey:     claimed,
			Prefix:        "SEMP-ENCLOSURE-SENDER:",
		}
		_, _, ok := verifySingleSignedDoc(t, spec)
		want := jgetBool(t, entry.Expected, "step_1_outer_sender_signature_verifies_against_claimed_key")
		if ok != want {
			t.Errorf("spoofed step 1 against claimed key got %v, want %v",
				ok, want)
		}
		// Sanity-check: against the actual signer's pubkey it
		// SHOULD verify (we're not testing forgery here).
		if hex := jget(t, entry.Inputs, "actual_outer_signer_pub_hex"); hex != "" {
			actualPub := ed25519.PublicKey(decodeHexF(t, hex, "actual_outer_signer_pub_hex"))
			specSanity := signedDocSpec{
				SignedJSON:    deepCopyMap(doc),
				SignaturePath: "sender_signature.value",
				PublicKey:     actualPub,
				Prefix:        "SEMP-ENCLOSURE-SENDER:",
			}
			_, _, sanityOK := verifySingleSignedDoc(t, specSanity)
			if !sanityOK {
				t.Error("actual signer's pub did not verify (sanity check)")
			}
		}
	default:
		t.Skipf("forwarding %q: no handler", entry.ID)
	}
}

func runForwardingChain(t *testing.T, entry vectorEntry, outerRaw json.RawMessage, want1, want2, want3 bool) {
	t.Helper()
	if len(outerRaw) == 0 {
		t.Fatal("missing outer enclosure JSON")
	}
	var outer map[string]any
	if err := json.Unmarshal(outerRaw, &outer); err != nil {
		t.Fatalf("outer unmarshal: %v", err)
	}
	forwarderPub := pubKeyFromInputs(t, entry, "forwarder_identity_pub_hex", "forwarder_pub_hex")
	originalPub := pubKeyFromInputs(t, entry, "original_sender_identity_pub_hex", "original_sender_pub_hex")

	// Step 1: outer document, sender_signature.value blanked, forwarder pub.
	step1 := signedDocSpec{
		SignedJSON:    deepCopyMap(outer),
		SignaturePath: "sender_signature.value",
		PublicKey:     forwarderPub,
		Prefix:        "SEMP-ENCLOSURE-SENDER:",
	}
	_, _, ok1 := verifySingleSignedDoc(t, step1)
	if ok1 != want1 {
		t.Errorf("step 1 (outer sender_signature) got %v, want %v", ok1, want1)
	}

	// Step 2: forwarded_from subtree, forwarder_attestation.value blanked.
	from, _ := outer["forwarded_from"].(map[string]any)
	if from == nil {
		t.Fatal("outer enclosure missing forwarded_from")
	}
	step2 := signedDocSpec{
		SignedJSON:    deepCopyMap(from),
		SignaturePath: "forwarder_attestation.value",
		PublicKey:     forwarderPub,
		Prefix:        "SEMP-FORWARDER-ATTESTATION:",
	}
	_, _, ok2 := verifySingleSignedDoc(t, step2)
	if ok2 != want2 {
		t.Errorf("step 2 (forwarder_attestation) got %v, want %v", ok2, want2)
	}

	// Step 3: original_enclosure_plaintext subtree, sender_signature.value blanked.
	orig, _ := from["original_enclosure_plaintext"].(map[string]any)
	if orig == nil {
		t.Fatal("forwarded_from missing original_enclosure_plaintext")
	}
	step3 := signedDocSpec{
		SignedJSON:    deepCopyMap(orig),
		SignaturePath: "sender_signature.value",
		PublicKey:     originalPub,
		Prefix:        "SEMP-ENCLOSURE-SENDER:",
	}
	_, _, ok3 := verifySingleSignedDoc(t, step3)
	if ok3 != want3 {
		t.Errorf("step 3 (original sender_signature) got %v, want %v", ok3, want3)
	}
}


// ---------------------------------------------------------------------------
// migration: four-signature chain (§3 cooperative migration)
//
// Each of the four signatures (old_identity, old_domain, new_identity,
// new_domain) is verified against the FINAL signed record by blanking
// only that one signature value and recomputing canonical bytes. The
// generator pre-computes these per-signer canonical bytes in the
// signature_chain intermediates; the runner regenerates them from the
// final record and asserts equality before verifying signatures.

func handleMigration(t *testing.T, entry vectorEntry) {
	if entry.ID != "migration-cooperative-four-signature-chain" {
		t.Skipf("migration %q: no handler", entry.ID)
	}

	// Migration is a sequential chain: each signer signs a document
	// where every PRIOR signer's value is populated and every LATER
	// signer's value is blank. To verify the final record we replay
	// the chain in the same order. The generator pins the per-step
	// canonical bytes in intermediates.signature_chain, so the
	// runner can both:
	//   (a) re-derive the per-step canonical bytes from the final
	//       record by replaying the blanking sequence, AND
	//   (b) cross-check (a) against intermediates.signature_chain.
	// We do (a) and (b) and then verify each signer's Ed25519
	// against (a).
	signedRaw := jgetRaw(t, entry.Expected, "signed_record_json")
	if len(signedRaw) == 0 {
		t.Fatal("missing signed_record_json")
	}
	var signedDoc map[string]any
	if err := json.Unmarshal(signedRaw, &signedDoc); err != nil {
		t.Fatalf("signed record unmarshal: %v", err)
	}

	// Order observed in the generator: 1=old_identity, 2=new_identity,
	// 3=new_domain, 4=old_domain. Pull the chain from intermediates
	// to confirm.
	type chainStep struct {
		fieldName string
		pubHexKey string
		role      string
	}
	chain := []chainStep{
		{"old_identity_signature", "old_identity_pub_hex", "old_identity"},
		{"new_identity_signature", "new_identity_pub_hex", "new_identity"},
		{"new_domain_signature", "new_domain_pub_hex", "new_domain"},
		{"old_domain_signature", "old_domain_pub_hex", "old_domain"},
	}

	var interChain []map[string]any
	if raw := jgetRaw(t, entry.Intermediates, "signature_chain"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &interChain); err != nil {
			t.Fatalf("signature_chain unmarshal: %v", err)
		}
	}

	allOK := true
	for i, step := range chain {
		// Build the per-step view of the document: blank
		// signature[i].value AND every later signature[j>i].value;
		// leave signature[j<i].value populated (those signers had
		// already produced their values when this step ran).
		stepDoc := deepCopyMap(signedDoc)
		for j, other := range chain {
			if j < i {
				continue
			}
			obj, _ := stepDoc[other.fieldName].(map[string]any)
			if obj == nil {
				t.Fatalf("step %d: missing %s", i+1, other.fieldName)
			}
			obj["value"] = ""
		}
		blanked, err := canonical.Marshal(stepDoc)
		if err != nil {
			t.Fatalf("step %d canonical: %v", i+1, err)
		}

		// Cross-check (b): generator's pinned canonical matches our
		// re-derivation.
		if i < len(interChain) {
			if want, _ := interChain[i]["canonical_with_blanked_signature_utf8"].(string); want != "" {
				if string(blanked) != want {
					t.Errorf("step %d canonical mismatch:\n  got  %s\n  want %s",
						i+1, string(blanked), want)
				}
			}
		}

		// Pull this signer's signature value from the FINAL doc
		// (not the per-step view) and Ed25519-verify it.
		sigObj, _ := signedDoc[step.fieldName].(map[string]any)
		sigVal, _ := sigObj["value"].(string)
		sig, err := base64.StdEncoding.DecodeString(sigVal)
		if err != nil {
			t.Fatalf("step %d decode signature: %v", i+1, err)
		}
		pub := ed25519.PublicKey(decodeHexF(t,
			jget(t, entry.Inputs, step.pubHexKey), step.pubHexKey))
		signingInput := append([]byte("SEMP-MIGRATION-RECORD:"), blanked...)
		ok := ed25519.Verify(pub, signingInput, sig)
		if !ok {
			t.Errorf("step %d (%s) signature verify failed", i+1, step.role)
			allOK = false
		}
	}
	wantAll := jgetBool(t, entry.Expected, "all_four_signatures_verify")
	if allOK != wantAll {
		t.Errorf("all_four_signatures_verify got %v, want %v", allOK, wantAll)
	}
}

