package handshake

import (
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
)

// Server drives the server side of a SEMP client handshake. It owns the
// server's ephemeral key pair, the proof-of-work decision, and the policy
// hooks (block list lookup, capacity check, capability negotiation).
//
// Lifecycle:
//
//	s := handshake.NewServer(suite, store, policy)
//	resp, _ := s.OnInit(initBytes)        // may return PoWRequired bytes
//	// ... optional PoW round trip ...
//	accepted, sess, err := s.OnConfirm(confirmBytes)
//	// transmit accepted; session is ready
type Server struct {
	suite  crypto.Suite
	store  keys.Store
	policy Policy

	// internal state populated by OnInit and consumed by OnConfirm.
	sessionID     string
	ephemeralPriv []byte
	clientNonce   []byte
	serverNonce   []byte
}

// Policy is the set of decisions a server delegates to its operator: should
// this handshake be PoW-gated, is the sender blocked, what TTL should the
// session get, what permissions should be granted on success.
type Policy interface {
	// RequirePoW returns a non-nil challenge if the server requires the
	// client to solve a PoW before proceeding.
	RequirePoW(initNonce, transport string) *PoWRequired

	// BlockedDomain reports whether the given domain is blocked at the
	// pre-handshake level. SEMP servers MUST check block lists before
	// completing a handshake (DESIGN.md §7).
	BlockedDomain(domain string) bool

	// SessionTTL returns the lifetime in seconds for a session granted to
	// the given client identity.
	SessionTTL(identity string) int

	// Permissions returns the granted permissions for the given client
	// identity (e.g. "send", "receive", "create_group").
	Permissions(identity string) []string
}

// NewServer constructs a Server. suite controls algorithm choices, store
// holds the server's domain key and the published user keys, and policy
// supplies operator decisions.
func NewServer(suite crypto.Suite, store keys.Store, policy Policy) *Server {
	return &Server{
		suite:  suite,
		store:  store,
		policy: policy,
	}
}

// OnInit processes a message 1 (init/client) and returns either:
//   - a serialized PoWRequired (the caller transmits it and waits for the
//     pow_solution before calling OnInit again with the original message)
//   - a serialized ServerResponse (the caller transmits it and waits for
//     the client's confirm)
//   - an error (the caller should serialize a Rejected and close)
//
// TODO(HANDSHAKE.md §2.2 – §2.3): parse, run policy.RequirePoW and
// policy.BlockedDomain, generate ephemeral key pair, build ServerResponse
// signed with the domain key.
func (s *Server) OnInit(data []byte) ([]byte, error) {
	_, _ = s, data
	return nil, nil
}

// OnPoWSolution processes a pow_solution message and either advances the
// handshake (returning the ServerResponse bytes) or rejects with pow_failed.
//
// TODO(HANDSHAKE.md §2.2b, REPUTATION.md §8.3.4): verify the solution.
func (s *Server) OnPoWSolution(data []byte) ([]byte, error) {
	_, _ = s, data
	return nil, nil
}

// OnConfirm processes message 3 (confirm/client), verifies the encrypted
// identity proof, and returns either the Accepted bytes plus a fully
// initialized Session, or a Rejected.
//
// TODO(HANDSHAKE.md §2.5 – §2.7): decrypt the identity proof using
// K_enc_c2s, verify identity_signature against the client's published
// long-term key, build the Accepted message signed with the domain key.
func (s *Server) OnConfirm(data []byte) (accepted []byte, sess *session.Session, err error) {
	_, _ = s, data
	return nil, nil, nil
}

// Erase wipes the server-side ephemeral private key and any retained
// handshake state.
func (s *Server) Erase() {
	if s == nil {
		return
	}
	crypto.Zeroize(s.ephemeralPriv)
	crypto.Zeroize(s.clientNonce)
	crypto.Zeroize(s.serverNonce)
	s.ephemeralPriv = nil
}
