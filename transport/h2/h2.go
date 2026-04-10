package h2

import (
	"context"

	"github.com/semp-dev/semp-go/transport"
)

// Path constants for the HTTP/2 binding (TRANSPORT.md §4.2.1).
const (
	PathDiscovery = "/v1/discovery"
	PathKeys      = "/v1/keys"
	PathHandshake = "/v1/handshake"
	PathEnvelope  = "/v1/envelope"
	PathSession   = "/v1/session/" // append session id
)

// HeaderSessionID is the response header that the server uses to correlate
// subsequent handshake POSTs with the in-progress handshake (TRANSPORT.md
// §4.2.3).
const HeaderSessionID = "Semp-Session-Id"

// ContentType is the JSON content type used for all SEMP HTTP/2 bodies.
const ContentType = "application/json; charset=utf-8"

// Transport is the HTTP/2 implementation of transport.Transport.
type Transport struct{}

// New returns a fresh HTTP/2 Transport.
func New() *Transport { return &Transport{} }

// ID returns transport.IDHTTP2.
func (*Transport) ID() transport.ID { return transport.IDHTTP2 }

// Profiles reports that HTTP/2 satisfies both synchronous and asynchronous
// profiles.
func (*Transport) Profiles() transport.Profile { return transport.ProfileBoth }

// Dial opens an HTTPS / HTTP/2 connection.
//
// TODO(TRANSPORT.md §4.2): implement using net/http with http2.Transport.
func (*Transport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	_, _ = ctx, endpoint
	return nil, nil
}

// Listen starts an HTTP/2 server bound to addr.
//
// TODO(TRANSPORT.md §4.2): implement.
func (*Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	_, _ = ctx, addr
	return nil, nil
}
