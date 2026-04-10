package handshake

import (
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
)

// Client drives the client side of a SEMP client handshake. It owns the
// ephemeral key pair and the partial state needed to derive the session
// secret. The state machine never performs network I/O directly; the caller
// moves bytes between this struct and the underlying transport.
//
// Lifecycle:
//
//	c := handshake.NewClient(suite, store, identity)
//	initBytes, _ := c.Init()
//	// transmit initBytes; read the server's response
//	confirmBytes, sess, _ := c.OnResponse(responseBytes)
//	// transmit confirmBytes; read the server's accepted/rejected
//	_ = c.OnAccepted(acceptedBytes)
//	// session is now usable
//
// If the server returns a pow_required message before the response, the
// caller MUST call OnPoWRequired before retrying for the response.
type Client struct {
	suite    crypto.Suite
	store    keys.PrivateStore
	identity string

	// nonce, ephemeralPriv, ephemeralPub, etc. are populated by Init.
	nonce         []byte
	ephemeralPub  []byte
	ephemeralPriv []byte
}

// NewClient constructs a Client. suite controls the algorithm choices,
// store provides the user's long-term identity private key, and identity is
// the user's full address (e.g. "user@example.com").
func NewClient(suite crypto.Suite, store keys.PrivateStore, identity string) *Client {
	return &Client{
		suite:    suite,
		store:    store,
		identity: identity,
	}
}

// Init produces the message 1 (init/client) bytes.
//
// TODO(HANDSHAKE.md §2.2): generate a fresh nonce and ephemeral key pair,
// build the ClientInit struct with capabilities advertised by suite, then
// canonical-marshal it.
func (c *Client) Init() ([]byte, error) {
	_ = c
	return nil, nil
}

// OnPoWRequired processes a pow_required message and returns the bytes of
// the pow_solution message to send next.
//
// TODO(HANDSHAKE.md §2.2a–b, REPUTATION.md §8.3): verify ServerSignature on
// the challenge, solve via SolveChallenge, then marshal the solution.
func (c *Client) OnPoWRequired(data []byte) ([]byte, error) {
	_, _ = c, data
	return nil, nil
}

// OnResponse processes the server's response (message 2), derives the
// session secret, and returns the confirm (message 3) bytes plus a partially
// initialized Session that the caller will finalize on OnAccepted.
//
// TODO(HANDSHAKE.md §2.3 – §2.5, SESSION.md §2.1): verify ServerSignature
// against the server's published domain key, perform the ephemeral key
// agreement, derive the five session keys, build the encrypted identity
// proof block, compute the confirmation hash, marshal the confirm message.
func (c *Client) OnResponse(data []byte) (confirm []byte, sess *session.Session, err error) {
	_, _ = c, data
	return nil, nil, nil
}

// OnAccepted processes the server's accepted message and finalizes the
// Session created by OnResponse. After OnAccepted returns nil, the session
// is ready to send envelopes.
//
// TODO(HANDSHAKE.md §2.7, SESSION.md §2.6): verify ServerSignature on the
// accepted message, set Session.State to StateActive, populate
// Session.EstablishedAt, TTL, and ExpiresAt from the response.
func (c *Client) OnAccepted(data []byte, sess *session.Session) error {
	_, _, _ = c, data, sess
	return nil
}

// OnRejected processes the server's rejected message and returns the
// corresponding *semp.Error.
//
// TODO(HANDSHAKE.md §4.1, ERRORS.md §2): parse the reason_code and convert
// to a *semp.Error so callers can branch on its Code.
func (c *Client) OnRejected(data []byte) error {
	_, _ = c, data
	return nil
}

// Erase wipes the ephemeral private key and any retained state. Callers
// MUST invoke Erase if the handshake is abandoned without completing.
func (c *Client) Erase() {
	if c == nil {
		return
	}
	crypto.Zeroize(c.ephemeralPriv)
	crypto.Zeroize(c.nonce)
	c.ephemeralPriv = nil
	c.ephemeralPub = nil
}
