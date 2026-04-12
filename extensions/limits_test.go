package extensions_test

import (
	"errors"
	"strings"
	"testing"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/extensions"
)

// -----------------------------------------------------------------------------
// MaxBytesFor
// -----------------------------------------------------------------------------

// TestMaxBytesForKnownLayers confirms every known layer returns the
// exact value from EXTENSIONS.md §4.1.
func TestMaxBytesForKnownLayers(t *testing.T) {
	tests := []struct {
		layer extensions.Layer
		want  int
	}{
		{extensions.LayerPostmark, extensions.MaxBytesPostmark},
		{extensions.LayerSeal, extensions.MaxBytesSeal},
		{extensions.LayerBrief, extensions.MaxBytesBrief},
		{extensions.LayerEnclosure, extensions.MaxBytesEnclosure},
		{extensions.LayerHandshake, extensions.MaxBytesHandshake},
		{extensions.LayerDiscovery, extensions.MaxBytesDiscovery},
		{extensions.LayerBlockEntry, extensions.MaxBytesBlockEntry},
	}
	for _, tc := range tests {
		if got := extensions.MaxBytesFor(tc.layer); got != tc.want {
			t.Errorf("MaxBytesFor(%s) = %d, want %d", tc.layer, got, tc.want)
		}
	}
}

// TestMaxBytesForSpecExact confirms the spec-mandated constants match
// the raw values listed in EXTENSIONS.md §4.1. If the spec changes
// these, this test fires so we see it on every run.
func TestMaxBytesForSpecExact(t *testing.T) {
	if extensions.MaxBytesPostmark != 4096 {
		t.Errorf("MaxBytesPostmark = %d, want 4096 (§4.1)", extensions.MaxBytesPostmark)
	}
	if extensions.MaxBytesSeal != 4096 {
		t.Errorf("MaxBytesSeal = %d, want 4096 (§4.1)", extensions.MaxBytesSeal)
	}
	if extensions.MaxBytesBrief != 16384 {
		t.Errorf("MaxBytesBrief = %d, want 16384 (§4.1)", extensions.MaxBytesBrief)
	}
	if extensions.MaxBytesEnclosure != 65536 {
		t.Errorf("MaxBytesEnclosure = %d, want 65536 (§4.1)", extensions.MaxBytesEnclosure)
	}
}

// TestMaxBytesForUnknownLayer returns the most permissive value.
func TestMaxBytesForUnknownLayer(t *testing.T) {
	got := extensions.MaxBytesFor(extensions.Layer("my.custom/v1"))
	if got != extensions.MaxBytesEnclosure {
		t.Errorf("unknown layer MaxBytes = %d, want %d", got, extensions.MaxBytesEnclosure)
	}
}

// -----------------------------------------------------------------------------
// ValidateSize
// -----------------------------------------------------------------------------

// TestValidateSizeEmptyMap confirms nil and empty maps pass at every
// layer — the empty `{}` is 2 bytes and fits everywhere.
func TestValidateSizeEmptyMap(t *testing.T) {
	for _, layer := range []extensions.Layer{
		extensions.LayerPostmark,
		extensions.LayerSeal,
		extensions.LayerBrief,
		extensions.LayerEnclosure,
	} {
		if err := extensions.ValidateSize(layer, nil); err != nil {
			t.Errorf("ValidateSize(%s, nil) = %v, want nil", layer, err)
		}
		if err := extensions.ValidateSize(layer, extensions.Map{}); err != nil {
			t.Errorf("ValidateSize(%s, {}) = %v, want nil", layer, err)
		}
	}
}

// TestValidateSizeAcceptsSmallMap confirms a modestly sized map fits
// every layer.
func TestValidateSizeAcceptsSmallMap(t *testing.T) {
	m := extensions.Map{
		"semp.dev/priority": extensions.Entry{
			Required: false,
			Data:     map[string]any{"level": "normal"},
		},
	}
	for _, layer := range []extensions.Layer{
		extensions.LayerPostmark,
		extensions.LayerSeal,
		extensions.LayerBrief,
		extensions.LayerEnclosure,
	} {
		if err := extensions.ValidateSize(layer, m); err != nil {
			t.Errorf("ValidateSize(%s, small) = %v, want nil", layer, err)
		}
	}
}

// TestValidateSizeRejectsOversizePostmark confirms an oversize map
// at the 4 KB postmark layer is rejected with a SizeError.
func TestValidateSizeRejectsOversizePostmark(t *testing.T) {
	m := extensions.Map{
		"semp.dev/priority": extensions.Entry{
			Required: false,
			// Data payload sized to blow past 4 KB.
			Data: strings.Repeat("x", 5000),
		},
	}
	err := extensions.ValidateSize(extensions.LayerPostmark, m)
	if err == nil {
		t.Fatal("oversize postmark map should have been rejected")
	}
	var se *extensions.SizeError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SizeError, got %T: %v", err, err)
	}
	if se.Layer != extensions.LayerPostmark {
		t.Errorf("SizeError.Layer = %s, want postmark", se.Layer)
	}
	if se.Max != extensions.MaxBytesPostmark {
		t.Errorf("SizeError.Max = %d, want %d", se.Max, extensions.MaxBytesPostmark)
	}
	if se.Size <= se.Max {
		t.Errorf("SizeError.Size = %d, want > Max=%d", se.Size, se.Max)
	}
	if se.ReasonCode() != semp.ReasonExtensionSizeExceeded {
		t.Errorf("ReasonCode = %s, want extension_size_exceeded", se.ReasonCode())
	}
}

// TestValidateSizeBriefLargerThanPostmark confirms a 10 KB map that
// fails at postmark passes at brief.
func TestValidateSizeBriefLargerThanPostmark(t *testing.T) {
	m := extensions.Map{
		"semp.dev/notes": extensions.Entry{
			Required: false,
			Data:     strings.Repeat("x", 10000),
		},
	}
	if err := extensions.ValidateSize(extensions.LayerPostmark, m); err == nil {
		t.Error("10 KB map should fail at postmark")
	}
	if err := extensions.ValidateSize(extensions.LayerBrief, m); err != nil {
		t.Errorf("10 KB map at brief = %v, want nil", err)
	}
}

// -----------------------------------------------------------------------------
// Validate
// -----------------------------------------------------------------------------

// TestValidateAcceptsRegisteredOptional confirms an optional
// extension that is registered passes Validate.
func TestValidateAcceptsRegisteredOptional(t *testing.T) {
	m := extensions.Map{
		"semp.dev/priority": extensions.Entry{Required: false},
	}
	if err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerPostmark, m); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestValidateAcceptsUnregisteredOptional confirms an unregistered
// optional extension is silently accepted per EXTENSIONS.md §3.2.
func TestValidateAcceptsUnregisteredOptional(t *testing.T) {
	m := extensions.Map{
		"semp.dev/unknown-future-feature": extensions.Entry{Required: false},
	}
	if err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerBrief, m); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestValidateRejectsUnregisteredRequired confirms a required
// extension that is NOT in the registry fires UnsupportedError at
// the semp.dev/ namespace.
func TestValidateRejectsUnregisteredRequired(t *testing.T) {
	m := extensions.Map{
		"semp.dev/unknown-future-feature": extensions.Entry{Required: true},
	}
	err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerBrief, m)
	if err == nil {
		t.Fatal("required unknown semp.dev/ extension should have been rejected")
	}
	var ue *extensions.UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *UnsupportedError, got %T: %v", err, err)
	}
	if ue.Key != "semp.dev/unknown-future-feature" {
		t.Errorf("UnsupportedError.Key = %q, want semp.dev/unknown-future-feature", ue.Key)
	}
	if ue.ReasonCode() != semp.ReasonExtensionUnsupported {
		t.Errorf("ReasonCode = %s, want extension_unsupported", ue.ReasonCode())
	}
}

// TestValidateAllowsRequiredVendorExtension confirms a required
// vendor extension is accepted even without registry presence
// because the registry is authoritative only for the semp.dev/
// namespace.
func TestValidateAllowsRequiredVendorExtension(t *testing.T) {
	m := extensions.Map{
		"vendor.example.com/proprietary": extensions.Entry{Required: true},
	}
	if err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerBrief, m); err != nil {
		t.Errorf("required vendor extension should pass: %v", err)
	}
}

// TestValidateAllowsRequiredExperimentalExtension confirms a
// required x- extension is accepted — the operator opted in.
func TestValidateAllowsRequiredExperimentalExtension(t *testing.T) {
	m := extensions.Map{
		"x-my-experiment": extensions.Entry{Required: true},
	}
	if err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerBrief, m); err != nil {
		t.Errorf("required x- extension should pass: %v", err)
	}
}

// TestValidateRejectsRequiredOnWrongLayer confirms a required
// semp.dev/ extension used at a layer it was NOT registered for
// produces an UnsupportedError. `semp.dev/priority` is registered
// for postmark only, so using it as required at brief is invalid.
func TestValidateRejectsRequiredOnWrongLayer(t *testing.T) {
	m := extensions.Map{
		"semp.dev/priority": extensions.Entry{Required: true},
	}
	err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerBrief, m)
	if err == nil {
		t.Fatal("priority is postmark-only; required at brief should be rejected")
	}
	var ue *extensions.UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *UnsupportedError, got %T: %v", err, err)
	}
}

// TestValidateRejectsMalformedKey confirms a key that fails
// ValidateKey produces a KeyError.
func TestValidateRejectsMalformedKey(t *testing.T) {
	m := extensions.Map{
		"bad key with spaces": extensions.Entry{Required: false},
	}
	err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerBrief, m)
	if err == nil {
		t.Fatal("malformed key should have been rejected")
	}
	var ke *extensions.KeyError
	if !errors.As(err, &ke) {
		t.Fatalf("expected *KeyError, got %T: %v", err, err)
	}
	if !strings.Contains(ke.Error(), "bad key with spaces") {
		t.Errorf("error should include the bad key: %v", ke)
	}
}

// TestValidateNilRegistryAllowsEverything confirms passing a nil
// registry skips the registry check entirely — every syntactically
// valid key passes regardless of required/optional.
func TestValidateNilRegistryAllowsEverything(t *testing.T) {
	m := extensions.Map{
		"semp.dev/anything": extensions.Entry{Required: true},
		"vendor.example.com/feature":  extensions.Entry{Required: true},
		"x-test": extensions.Entry{Required: true},
	}
	if err := extensions.Validate(nil, extensions.LayerBrief, m); err != nil {
		t.Errorf("nil registry should accept all valid keys: %v", err)
	}
}

// TestValidateEmptyMap is a short-circuit path.
func TestValidateEmptyMap(t *testing.T) {
	if err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerPostmark, nil); err != nil {
		t.Errorf("nil map: %v", err)
	}
	if err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerPostmark, extensions.Map{}); err != nil {
		t.Errorf("empty map: %v", err)
	}
}

// TestValidateChecksSizeAfterKeys confirms Validate catches size
// errors even when every key is structurally valid.
func TestValidateChecksSizeAfterKeys(t *testing.T) {
	m := extensions.Map{
		"semp.dev/priority": extensions.Entry{
			Required: false,
			Data:     strings.Repeat("x", 5000),
		},
	}
	err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerPostmark, m)
	if err == nil {
		t.Fatal("oversize should be rejected")
	}
	var se *extensions.SizeError
	if !errors.As(err, &se) {
		t.Errorf("expected *SizeError, got %T: %v", err, err)
	}
}

// TestValidateDeterministicErrorOrdering confirms the first failing
// key is reported in sorted order — not map iteration order — so
// two servers given the same input produce the same error.
func TestValidateDeterministicErrorOrdering(t *testing.T) {
	// Two malformed keys; in sorted order "a bad" comes before
	// "z bad". Validate should always report "a bad" first.
	m := extensions.Map{
		"z bad": extensions.Entry{Required: false},
		"a bad": extensions.Entry{Required: false},
	}
	for i := 0; i < 20; i++ {
		err := extensions.Validate(extensions.DefaultRegistry, extensions.LayerBrief, m)
		if err == nil {
			t.Fatal("expected error")
		}
		var ke *extensions.KeyError
		if !errors.As(err, &ke) {
			t.Fatalf("expected *KeyError, got %T", err)
		}
		if ke.Key != "a bad" {
			t.Errorf("iteration %d: first failing key = %q, want %q", i, ke.Key, "a bad")
		}
	}
}
