package quic

import (
	"context"

	"github.com/semp-dev/semp-go/transport"
)

// Transport is the QUIC implementation of transport.Transport.
type Transport struct{}

// New returns a fresh QUIC Transport.
func New() *Transport { return &Transport{} }

// ID returns transport.IDQUIC.
func (*Transport) ID() transport.ID { return transport.IDQUIC }

// Profiles reports that QUIC satisfies both synchronous and asynchronous
// profiles.
func (*Transport) Profiles() transport.Profile { return transport.ProfileBoth }

// Dial opens a QUIC / HTTP/3 connection to endpoint.
//
// TODO(TRANSPORT.md §4.3): implement using github.com/quic-go/quic-go and
// the HTTP/3 client.
func (*Transport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	_, _ = ctx, endpoint
	return nil, nil
}

// Listen starts a QUIC server bound to addr.
//
// TODO(TRANSPORT.md §4.3): implement.
func (*Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	_, _ = ctx, addr
	return nil, nil
}
