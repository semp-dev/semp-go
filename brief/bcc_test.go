package brief_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/brief"
	"github.com/semp-dev/semp-go/extensions"
)

// briefWithBCC is a tiny fixture builder used by every test in this
// file. The brief carries a realistic mix of fields so that
// SplitForBCC's preservation guarantees are exercised.
func briefWithBCC(bcc []brief.Address) *brief.Brief {
	return &brief.Brief{
		MessageID: "01JTESTMSG0000000000000001",
		From:      "alice@example.com",
		To:        []brief.Address{"bob@example.com", "carol@example.com"},
		CC:        []brief.Address{"dave@example.com"},
		BCC:       bcc,
		SentAt:    time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC),
		ThreadID:  "thread-1",
		Extensions: extensions.Map{
			"x.example": extensions.Entry{
				Required: false,
				Data:     "hello",
			},
		},
	}
}

// TestSplitForBCCNoRecipients confirms the zero-BCC case returns the
// input unchanged as a single-element slice.
func TestSplitForBCCNoRecipients(t *testing.T) {
	b := briefWithBCC(nil)
	out := brief.SplitForBCC(b)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if out[0] != b {
		t.Error("expected input returned by identity when BCC is empty")
	}
}

// TestSplitForBCCNilInput confirms the nil-input case returns nil.
func TestSplitForBCCNilInput(t *testing.T) {
	if got := brief.SplitForBCC(nil); got != nil {
		t.Errorf("SplitForBCC(nil) = %v, want nil", got)
	}
}

// TestSplitForBCCSingleRecipient exercises the N=1 case: the result
// contains (visible copy, one BCC copy). The visible copy has bcc
// stripped; the BCC copy has bcc containing only that recipient.
func TestSplitForBCCSingleRecipient(t *testing.T) {
	b := briefWithBCC([]brief.Address{"eve@example.com"})
	out := brief.SplitForBCC(b)
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2 (1 visible + 1 BCC)", len(out))
	}

	visible := out[0]
	if len(visible.BCC) != 0 {
		t.Errorf("visible copy BCC = %v, want empty", visible.BCC)
	}
	// To/CC/From/etc MUST be preserved byte-for-byte.
	if len(visible.To) != 2 || visible.To[0] != "bob@example.com" {
		t.Errorf("visible copy To = %v, want preserved", visible.To)
	}
	if visible.From != "alice@example.com" {
		t.Errorf("visible copy From = %q, want alice@example.com", visible.From)
	}
	if visible.MessageID != b.MessageID {
		t.Errorf("visible copy MessageID mismatch: got %q want %q",
			visible.MessageID, b.MessageID)
	}

	bccCopy := out[1]
	if len(bccCopy.BCC) != 1 || bccCopy.BCC[0] != "eve@example.com" {
		t.Errorf("BCC copy BCC = %v, want [eve@example.com]", bccCopy.BCC)
	}
	// To/CC preserved so the BCC recipient sees the same primary list.
	if len(bccCopy.To) != 2 || len(bccCopy.CC) != 1 {
		t.Errorf("BCC copy To/CC mismatch: To=%v CC=%v", bccCopy.To, bccCopy.CC)
	}
}

// TestSplitForBCCMultipleRecipients is the N>1 case. Each BCC
// recipient gets exactly one envelope copy containing only their own
// address, and the visible copy has no BCC at all.
func TestSplitForBCCMultipleRecipients(t *testing.T) {
	bcc := []brief.Address{
		"eve@example.com",
		"frank@example.com",
		"grace@example.com",
	}
	b := briefWithBCC(bcc)
	out := brief.SplitForBCC(b)
	if len(out) != 4 {
		t.Fatalf("len(out) = %d, want 4 (1 visible + 3 BCC)", len(out))
	}
	// Visible copy at index 0.
	if len(out[0].BCC) != 0 {
		t.Errorf("visible copy BCC = %v, want empty", out[0].BCC)
	}
	// Each BCC copy at index i+1 contains exactly bcc[i].
	for i, recipient := range bcc {
		got := out[i+1]
		if len(got.BCC) != 1 {
			t.Errorf("copy[%d].BCC length = %d, want 1", i+1, len(got.BCC))
			continue
		}
		if got.BCC[0] != recipient {
			t.Errorf("copy[%d].BCC = %v, want [%q]", i+1, got.BCC, recipient)
		}
	}
}

// TestSplitForBCCCopyIsolation confirms each BCC copy's BCC slice is
// a distinct backing array, so mutating one copy's BCC does not leak
// into another copy. This is the invariant a sending client relies on
// when it iterates the result calling Compose on each copy.
func TestSplitForBCCCopyIsolation(t *testing.T) {
	b := briefWithBCC([]brief.Address{"eve@example.com", "frank@example.com"})
	out := brief.SplitForBCC(b)
	// Mutate copy[1]'s BCC and confirm copy[2] is unaffected.
	out[1].BCC[0] = "mallory@evil.example"
	if out[2].BCC[0] != "frank@example.com" {
		t.Errorf("copy[2].BCC leaked across copies: got %v", out[2].BCC)
	}
}

// TestSplitForBCCJSONOmitsVisibleBCC confirms that the visible copy
// serializes to JSON without any `bcc` field at all, matching
// ENVELOPE.md §5.3 ("the bcc field is absent entirely from the
// envelope copies delivered to to and cc recipients").
func TestSplitForBCCJSONOmitsVisibleBCC(t *testing.T) {
	b := briefWithBCC([]brief.Address{"eve@example.com"})
	out := brief.SplitForBCC(b)
	raw, err := json.Marshal(out[0])
	if err != nil {
		t.Fatalf("Marshal visible: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := generic["bcc"]; present {
		t.Errorf("visible copy JSON contains bcc field; got %s", raw)
	}
	// The BCC-recipient copy, on the other hand, MUST have the bcc
	// field present and containing exactly one entry.
	raw2, err := json.Marshal(out[1])
	if err != nil {
		t.Fatalf("Marshal bcc copy: %v", err)
	}
	var generic2 map[string]any
	if err := json.Unmarshal(raw2, &generic2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	bccList, ok := generic2["bcc"].([]any)
	if !ok {
		t.Fatalf("bcc copy JSON missing bcc array; got %s", raw2)
	}
	if len(bccList) != 1 || bccList[0] != "eve@example.com" {
		t.Errorf("bcc copy JSON bcc = %v, want [eve@example.com]", bccList)
	}
}

// TestSplitForBCCPreservesExtensions confirms each returned copy
// points at the same extensions payload as the input. We intentionally
// share the Extensions map rather than deep-cloning because cloning
// arbitrary extension.Map values would require a recursive JSON
// round-trip and callers that want independent copies can do it
// themselves.
func TestSplitForBCCPreservesExtensions(t *testing.T) {
	b := briefWithBCC([]brief.Address{"eve@example.com"})
	out := brief.SplitForBCC(b)
	for i, copy := range out {
		if _, ok := copy.Extensions["x.example"]; !ok {
			t.Errorf("copy[%d] missing x.example extension", i)
		}
	}
}
