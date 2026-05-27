package quic_test

import (
	"context"
	"testing"

	"github.com/semp-dev/semp-go/transport"
	tquic "github.com/semp-dev/semp-go/transport/quic"
)

// TestTransportID confirms the wire-level transport identifier and
// supported profiles. Cheap and brittle-on-rename, which is exactly
// what we want for a public constant.
func TestTransportID(t *testing.T) {
	tr := tquic.New()
	if tr.ID() != transport.IDQUIC {
		t.Errorf("ID() = %q, want %q", tr.ID(), transport.IDQUIC)
	}
	if tr.Profiles() != transport.ProfileBoth {
		t.Errorf("Profiles() = %d, want ProfileBoth", tr.Profiles())
	}
}

// TestDialDelegatesHTTPSCheckToH2 confirms that the QUIC binding
// inherits the h2 binding's HTTPS-only requirement. Since QUIC's
// Dial wraps h2.Dial, a non-https URL must be rejected at construct
// time rather than producing a Conn that errors on first Send.
func TestDialDelegatesHTTPSCheckToH2(t *testing.T) {
	tr := tquic.New()
	_, err := tr.Dial(context.Background(), "http://127.0.0.1:1/")
	if err == nil {
		t.Fatal("Dial accepted a plain http:// URL")
	}
}
