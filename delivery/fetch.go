package delivery

import (
	"time"

	semp "github.com/semp-dev/semp-go"
)

// FetchType is the wire-level type discriminator for the demo-only fetch
// protocol used by the cmd/semp-cli `receive` subcommand.
//
// HANDSHAKE.md §4.6 explicitly leaves the client wakeup mechanism outside
// the scope of the spec: "How a server notifies a client that incoming
// messages are waiting is outside the scope of this specification.
// Implementations MAY use persistent WebSocket connections, long polling,
// or platform notification services such as APNs or FCM."
//
// SEMP_FETCH is the simplest possible such mechanism: the client, after
// completing the handshake, sends a single SEMP_FETCH request and the
// server responds with the contents of the client's inbox. It is fit for
// demo and test purposes only; a real deployment would use a long-lived
// notification stream or platform push.
const FetchType = "SEMP_FETCH"

// FetchStep is the discriminator for which fetch message variant this is.
type FetchStep string

// FetchStep values.
const (
	FetchStepRequest  FetchStep = "request"
	FetchStepResponse FetchStep = "response"
)

// FetchRequest is sent by the client to pull every waiting envelope from
// the server's inbox for the authenticated identity.
type FetchRequest struct {
	Type    string    `json:"type"`
	Step    FetchStep `json:"step"`
	Version string    `json:"version"`
}

// NewFetchRequest constructs a FetchRequest with the protocol version
// pre-populated.
func NewFetchRequest() *FetchRequest {
	return &FetchRequest{
		Type:    FetchType,
		Step:    FetchStepRequest,
		Version: semp.ProtocolVersion,
	}
}

// FetchResponse carries the envelopes the server is delivering. Each
// element of Envelopes is the base64-encoded canonical JSON of a single
// SEMP envelope (the same bytes the sender originally produced; the
// recipient runs envelope.Decode and OpenBrief / OpenEnclosure on each).
//
// Drained reports whether the server returned every envelope it had
// queued for the recipient. The demo server always sets this to true
// because the inbox is unbounded; production implementations might
// paginate and set Drained=false.
type FetchResponse struct {
	Type      string    `json:"type"`
	Step      FetchStep `json:"step"`
	Version   string    `json:"version"`
	Envelopes []string  `json:"envelopes"`
	Drained   bool      `json:"drained"`
	Timestamp time.Time `json:"timestamp"`
}

// NewFetchResponse builds a fully-populated FetchResponse for the given
// envelope payloads. envelopes are passed as raw JSON byte slices and
// will be base64-encoded by the caller before transmission.
func NewFetchResponse(envelopesB64 []string) *FetchResponse {
	return &FetchResponse{
		Type:      FetchType,
		Step:      FetchStepResponse,
		Version:   semp.ProtocolVersion,
		Envelopes: envelopesB64,
		Drained:   true,
		Timestamp: time.Now().UTC(),
	}
}
