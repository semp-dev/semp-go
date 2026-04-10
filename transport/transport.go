package transport

import "context"

// ID is the wire-level transport identifier (TRANSPORT.md §5.1) used in
// discovery records and in the handshake init message's transport field.
type ID string

// Defined transport identifiers.
const (
	IDWebSocket ID = "ws"
	IDHTTP2     ID = "h2"
	IDQUIC      ID = "quic"
	IDgRPC      ID = "grpc"
	IDAMQP      ID = "amqp"
	IDKafka     ID = "kafka"
)

// Transport is the SEMP wire transport abstraction. Implementations MUST
// satisfy the seven minimum requirements in TRANSPORT.md §2: confidentiality
// (TLS 1.2+), server authentication, reliable ordered delivery, bidirectional
// messaging, message framing, binary-safe variable-length payloads, and
// connection lifecycle signaling.
type Transport interface {
	// ID returns the wire identifier for this transport.
	ID() ID

	// Profiles returns the bitmask of supported profiles (sync, async,
	// or both).
	Profiles() Profile

	// Dial opens a client connection to endpoint. The caller is
	// responsible for selecting endpoint from the discovery results.
	Dial(ctx context.Context, endpoint string) (Conn, error)

	// Listen starts a server listener bound to addr. The returned Listener
	// produces inbound Conns until the context is canceled or Close is
	// called on the listener.
	Listen(ctx context.Context, addr string) (Listener, error)
}

// Conn is a single bidirectional message channel between two SEMP peers.
// Implementations MUST guarantee in-order delivery of complete messages —
// the SEMP layer never reassembles fragments above this interface.
type Conn interface {
	// Send transmits a single SEMP message. The transport binding is
	// responsible for any chunking or framing required by the underlying
	// protocol.
	Send(ctx context.Context, msg []byte) error

	// Recv blocks until the next complete SEMP message is available, then
	// returns it. Returns an error on transport-level failure or context
	// cancellation.
	Recv(ctx context.Context) ([]byte, error)

	// Close closes the connection cleanly. Implementations MUST send a
	// transport-level close frame so that the peer can distinguish a
	// clean disconnect from a network failure (TRANSPORT.md §2.7).
	Close() error

	// Peer returns a human-readable identifier for the remote endpoint
	// (e.g. "wss://semp.example.com/v1/ws").
	Peer() string
}

// Listener is the inbound side of a transport binding.
type Listener interface {
	// Accept blocks until the next inbound Conn arrives.
	Accept(ctx context.Context) (Conn, error)

	// Close stops accepting new connections. Existing Conns are not
	// affected and must be closed explicitly.
	Close() error
}
