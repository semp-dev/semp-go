package largeattachment_test

import (
	"encoding/json"
	"testing"

	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/largeattachment"
)

func validItem(id string) largeattachment.Item {
	return largeattachment.Item{
		ID:             id,
		Filename:       id + ".bin",
		MimeType:       "application/octet-stream",
		PlaintextSize:  1,
		URL:            "https://blobs.example.com/" + id,
		CiphertextHash: "sha256:00",
		AEADAlgorithm:  largeattachment.AEADChaCha20Poly1305,
		AEADNonce:      "AAAAAAAAAAAAAAAA",
	}
}

func TestSetReadRoundTrip(t *testing.T) {
	a := validItem("att-1")
	b := validItem("att-2")
	m, err := largeattachment.SetOnExtensions(nil, a, b)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := largeattachment.ReadFromExtensions(m)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 || got[0].ID != "att-1" || got[1].ID != "att-2" {
		t.Errorf("read items = %+v", got)
	}
}

// TestReadDecodesGenericMapShape confirms ReadFromExtensions
// tolerates the wire-decoded form: after json.Unmarshal of an
// envelope, the entry Data is a map[string]any rather than a
// typed ExtensionData. The helper falls back to a marshal+unmarshal
// path so callers do not need to pre-decode.
func TestReadDecodesGenericMapShape(t *testing.T) {
	a := validItem("att-1")
	wireMap := extensions.Map{
		largeattachment.ExtensionKey: extensions.Entry{
			Required: false,
			Data: map[string]any{
				"items": []any{
					map[string]any{
						"id":              a.ID,
						"filename":        a.Filename,
						"mime_type":       a.MimeType,
						"plaintext_size":  a.PlaintextSize,
						"url":             a.URL,
						"ciphertext_hash": a.CiphertextHash,
						"aead_algorithm":  a.AEADAlgorithm,
						"aead_nonce":      a.AEADNonce,
					},
				},
			},
		},
	}
	got, err := largeattachment.ReadFromExtensions(wireMap)
	if err != nil {
		t.Fatalf("Read wire-shape: %v", err)
	}
	if len(got) != 1 || got[0].ID != "att-1" {
		t.Errorf("read items = %+v", got)
	}
}

// TestAppendMergesPreservingExisting confirms Append merges into
// an existing entry rather than overwriting.
func TestAppendMergesPreservingExisting(t *testing.T) {
	m, _ := largeattachment.SetOnExtensions(nil, validItem("att-1"))
	m, err := largeattachment.AppendToExtensions(m, validItem("att-2"))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, _ := largeattachment.ReadFromExtensions(m)
	if len(got) != 2 {
		t.Errorf("merged length = %d, want 2", len(got))
	}
}

// TestAppendRejectsDuplicateID confirms a colliding id is rejected
// rather than silently overwriting the prior entry.
func TestAppendRejectsDuplicateID(t *testing.T) {
	m, _ := largeattachment.SetOnExtensions(nil, validItem("att-1"))
	if _, err := largeattachment.AppendToExtensions(m, validItem("att-1")); err == nil {
		t.Error("Append accepted duplicate id")
	}
}

// TestFindByIDReturnsItemAndPresence confirms the lookup helper.
func TestFindByIDReturnsItemAndPresence(t *testing.T) {
	m, _ := largeattachment.SetOnExtensions(nil, validItem("att-1"))
	if it, ok := largeattachment.FindByID(m, "att-1"); !ok || it.ID != "att-1" {
		t.Errorf("FindByID hit: got (%+v, %v)", it, ok)
	}
	if _, ok := largeattachment.FindByID(m, "ghost"); ok {
		t.Error("FindByID returned ok=true for unknown id")
	}
}

// TestAppendValidatesItem confirms a malformed item is rejected.
func TestAppendValidatesItem(t *testing.T) {
	bad := validItem("att-1")
	bad.URL = "http://insecure.example.com/x" // plain HTTP -> ValidateURL fails
	if _, err := largeattachment.AppendToExtensions(nil, bad); err == nil {
		t.Error("Append accepted invalid item")
	}
}

// TestRemoveFromExtensions confirms removal works.
func TestRemoveFromExtensions(t *testing.T) {
	m, _ := largeattachment.SetOnExtensions(nil, validItem("att-1"))
	m = largeattachment.RemoveFromExtensions(m)
	if _, ok := m[largeattachment.ExtensionKey]; ok {
		t.Error("Remove did not delete entry")
	}
}

// TestRoundTripThroughJSON confirms the Set/Read pair survives a
// JSON marshal+unmarshal cycle, the round-trip every wire path
// goes through.
func TestRoundTripThroughJSON(t *testing.T) {
	m, _ := largeattachment.SetOnExtensions(nil, validItem("att-1"))
	bytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded extensions.Map
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got, err := largeattachment.ReadFromExtensions(decoded)
	if err != nil {
		t.Fatalf("Read after json round-trip: %v", err)
	}
	if len(got) != 1 || got[0].ID != "att-1" {
		t.Errorf("post-json items = %+v", got)
	}
}
