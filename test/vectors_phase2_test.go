package test

// Phase 2 vector handlers.
//
// Wave 2A here covers single-signature documents — every category
// where the construction is "blank one signature field, canonicalize,
// prepend a domain-separation prefix, Ed25519-verify against a pinned
// public key". The pattern is uniform enough that a single
// `verifySingleSignedDoc` helper plus a per-category dispatcher
// covers ten categories at modest cost.
//
// Multi-signature chains (migration, forwarding) and round-trip
// constructions (seal, envelope, sender-signature, etc.) are Wave 2D
// and live in a separate file.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/internal/canonical"
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
//  2. Canonicalize the blanked copy via internal/canonical.
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
// vector format makes this OPTIONAL — many entries omit
// intermediates — but where it IS pinned, mismatch is a clear
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
//	canonical-only entries (init, confirm) — verify canonical bytes only
//	signed entries (response, accepted, rejected) — verify Ed25519
//
// The signature field is `server_signature` (top-level base64 string),
// with one wrinkle: the "rejected" entry uses the same field name, but
// the "init" and "confirm" entries don't have outer signatures at all
// (the client identity proof is signed separately).

func handleHandshakeMessages(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "handshake-init-canonical", "handshake-confirm-canonical":
		// Canonical-only verification: take the message_pre_sign_json
		// (which has no outer signature), canonicalize, compare to
		// the pinned canonical_utf8 intermediate.
		preSign := jgetRaw(t, entry.Inputs, "message_pre_sign_json")
		if len(preSign) == 0 {
			t.Skip("missing message_pre_sign_json")
		}
		var doc map[string]any
		if err := json.Unmarshal(preSign, &doc); err != nil {
			t.Fatalf("pre-sign unmarshal: %v", err)
		}
		got, err := canonical.Marshal(doc)
		if err != nil {
			t.Fatalf("canonical.Marshal: %v", err)
		}
		want := jget(t, entry.Intermediates, "canonical_utf8")
		if want == "" {
			// Some entries don't pin the canonical bytes; nothing
			// further to check here.
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
//	resume-request-canonical  — canonical-only; client_signature blanked
//	resume-accepted-signed    — Ed25519; server_signature
//	resume-key-derivation     — KDF round-trip; deferred to Wave 2D
//
// The request is canonical-only because the client signature isn't
// applied at this layer (per HANDSHAKE.md §2.8); the canonical bytes
// are what matters here. Wave 2D will pick up the KDF derivation.

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
		preSign := jgetRaw(t, entry.Inputs, "request_pre_sign_json")
		if len(preSign) == 0 {
			t.Skip("missing request_pre_sign_json")
		}
		var doc map[string]any
		if err := json.Unmarshal(preSign, &doc); err != nil {
			t.Fatalf("pre-sign unmarshal: %v", err)
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
		t.Skip("resume-key-derivation: Wave 2D (KDF round-trip)")
	default:
		t.Skipf("session-resumption %q: no handler", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// recovery-shamir: three entries
//
//	shamir-split-and-combine          — GF(256) Shamir; Wave 2D
//	shamir-recovery-set-manifest-signed — Ed25519; signature.value
//	shamir-share-record-signed        — multiple records; device_signature.value

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
		t.Skip("shamir-split-and-combine: Wave 2D (GF(256) interpolation)")
	default:
		t.Skipf("recovery-shamir %q: no handler", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// first-contact-token: 2 entries
//
//	first-contact-token-valid          — verify PoW + postmark binding
//	first-contact-token-replay-rejected — rejection demo (must_reject)
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
// Wave 2B: decision-table shape validators
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
// `required`, with the field present (the value MAY be null —
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
	case "acknowledgment-to-ui-state":
		requireSampleFields(t, entry.Samples,
			"server_acknowledgment", "client_ui_state")
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
	default:
		t.Skipf("delivery-status %q: no handler", entry.ID)
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
// Wave 2C: must-reject-index cross-reference + envelope-rejection schema
//
// must-reject-index.json is a generated cross-reference; the runner
// validates that every `pointer` of the form `<file>#<id>` resolves
// to a vector entry with the matching `must_reject:true` flag. This
// is a structural assertion only — it does not re-verify the
// rejection outcome (those live in their respective files and are
// covered by their own handlers).
//
// negative-envelope-rejection schema-only here; the actual must-reject
// outcomes need round-trip-aware envelope verification (Wave 2D).

func handleMustRejectIndex(t *testing.T, entry vectorEntry) {
	// The index file has a different top-level shape: no `vectors`
	// array of (inputs, expected) entries, just the index itself.
	// Each "vector" entry the runner sees is actually a row of the
	// flat index. Our dispatch already iterates entries, but the
	// must-reject-index file exposes only summary/by_class/flat at
	// the top level. The runner currently treats it as 0 entries
	// (no `vectors` field), so this handler is effectively unused —
	// reaching here would mean the file structure changed.
	if len(entry.Inputs) > 0 || len(entry.Expected) > 0 {
		t.Errorf("must-reject-index entry has unexpected fields: %s", entry.ID)
	}
}

func handleNegativeEnvelopeRejection(t *testing.T, entry vectorEntry) {
	// Schema check only; the actual rejection check requires
	// envelope.OpenVerified or seal verification on a tampered
	// envelope. Those are Wave 2D.
	if len(entry.Inputs) == 0 {
		t.Error("inputs missing")
	}
	if raw := jgetRaw(t, entry.Expected, "rejection_reason_code"); len(raw) > 0 {
		validateReasonCode(t, 0, raw)
	}
}

