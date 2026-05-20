package h2

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// DefaultIdleTimeout is the default duration after which a server-side
// persistent session is closed if no POST arrives. A fresh value fires
// on every new POST carrying the session's Semp-Session-Id header.
const DefaultIdleTimeout = 60 * time.Second

// -----------------------------------------------------------------------------
// Client-side transport.Conn
// -----------------------------------------------------------------------------

// persistentClient adapts an *h2.Client to transport.Conn by interleaving
// Send and Recv calls into POST round trips. Each Send issues one POST and
// stores the response body; the next Recv returns that stored body.
//
// The adapter is turn-based: callers MUST follow the pattern
//
//	Send → Recv → Send → Recv → …
//
// which is exactly what the SEMP handshake and request-response
// flows do. This matches the HTTP/2 binding in TRANSPORT.md §4.2.3 where
// every client message is one POST and every server message is the
// corresponding POST response body, correlated across calls by the
// Semp-Session-Id header that h2.Client threads automatically.
//
// persistentClient is NOT safe for concurrent Send/Recv - the underlying
// *h2.Client is single-threaded and the turn buffer is a one-element slot.
type persistentClient struct {
	client *Client
	peer   string

	// pendingMu guards pending. Only one response is ever buffered at a
	// time because the contract is strict Send → Recv alternation.
	pendingMu sync.Mutex
	pending   []byte
	hasPending bool

	closeOnce sync.Once
	closed    chan struct{}
}

func newPersistentClient(cli *Client, peer string) *persistentClient {
	return &persistentClient{
		client: cli,
		peer:   peer,
		closed: make(chan struct{}),
	}
}

// Send POSTs msg to the remote endpoint and buffers the response body for
// the next Recv call. Returns an error if a previous response has not yet
// been consumed by Recv, or if the underlying POST fails.
func (pc *persistentClient) Send(ctx context.Context, msg []byte) error {
	if pc == nil || pc.client == nil {
		return errors.New("h2: nil persistent client")
	}
	select {
	case <-pc.closed:
		return errors.New("h2: persistent client closed")
	default:
	}

	pc.pendingMu.Lock()
	if pc.hasPending {
		pc.pendingMu.Unlock()
		return errors.New("h2: Send called before previous Recv - persistent client is turn-based")
	}
	pc.pendingMu.Unlock()

	resp, err := pc.client.Do(ctx, msg)
	if err != nil {
		return err
	}

	pc.pendingMu.Lock()
	pc.pending = resp
	pc.hasPending = true
	pc.pendingMu.Unlock()
	return nil
}

// Recv returns the response body buffered by the most recent Send. It
// blocks briefly only to observe Close; actual network I/O happened
// during Send.
func (pc *persistentClient) Recv(ctx context.Context) ([]byte, error) {
	if pc == nil {
		return nil, errors.New("h2: nil persistent client")
	}
	select {
	case <-pc.closed:
		return nil, io.EOF
	default:
	}

	pc.pendingMu.Lock()
	defer pc.pendingMu.Unlock()
	if !pc.hasPending {
		return nil, errors.New("h2: Recv called without a buffered response - call Send first")
	}
	body := pc.pending
	pc.pending = nil
	pc.hasPending = false
	return body, nil
}

// Close marks the client as closed; subsequent Send or Recv calls return
// errors. The underlying *http.Client is shared with the embedded
// h2.Client and is not torn down - callers that want to release the HTTP
// transport should do so themselves.
func (pc *persistentClient) Close() error {
	if pc == nil {
		return nil
	}
	pc.closeOnce.Do(func() { close(pc.closed) })
	return nil
}

// Peer returns the remote endpoint URL.
func (pc *persistentClient) Peer() string {
	if pc == nil {
		return ""
	}
	return pc.peer
}

// SessionID exposes the Semp-Session-Id the underlying h2.Client captured
// from the most recent response. Primarily useful for diagnostics.
func (pc *persistentClient) SessionID() string {
	if pc == nil || pc.client == nil {
		return ""
	}
	return pc.client.SessionID()
}

