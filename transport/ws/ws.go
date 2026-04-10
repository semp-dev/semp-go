package ws

import (
	"context"

	"github.com/semp-dev/semp-go/transport"
)

// Subprotocol is the WebSocket subprotocol identifier sent in the HTTP
// Upgrade request and confirmed by the server in its Upgrade response.
// Servers that do not confirm this value MUST cause the client to close
// the connection (TRANSPORT.md §4.1.1).
const Subprotocol = "semp.v1"

// PingInterval is the recommended keepalive ping interval for long-lived
// SEMP WebSocket sessions (TRANSPORT.md §4.1.3).
const PingInterval = 30 // seconds

// Transport is the WebSocket implementation of transport.Transport.
type Transport struct{}

// New returns a fresh WebSocket Transport.
func New() *Transport { return &Transport{} }

// ID returns transport.IDWebSocket.
func (*Transport) ID() transport.ID { return transport.IDWebSocket }

// Profiles reports that WebSocket satisfies both synchronous and
// asynchronous profiles.
func (*Transport) Profiles() transport.Profile { return transport.ProfileBoth }

// Dial opens a WSS connection to endpoint and negotiates the semp.v1
// subprotocol.
//
// TODO(TRANSPORT.md §4.1.1): implement using github.com/coder/websocket.
func (*Transport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	_, _ = ctx, endpoint
	return nil, nil
}

// Listen starts a WebSocket server bound to addr.
//
// TODO(TRANSPORT.md §4.1): implement.
func (*Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	_, _ = ctx, addr
	return nil, nil
}
