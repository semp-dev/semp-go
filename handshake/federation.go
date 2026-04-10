package handshake

import (
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
)

// FederationType identifies the federation mode requested by the initiator
// (HANDSHAKE.md §5.2.1).
type FederationType string

// FederationType values.
const (
	FederationFull    FederationType = "full"
	FederationRelay   FederationType = "relay"
	FederationLimited FederationType = "limited"
)

// ServerInit is the message 1 sent by an initiating server in a federation
// handshake (HANDSHAKE.md §5.2). Unlike the client init, the server init
// includes the originating server's domain identity in plaintext.
type ServerInit struct {
	Type                string         `json:"type"`
	Step                Step           `json:"step"`  // StepInit
	Party               Party          `json:"party"` // PartyServer
	Version             string         `json:"version"`
	Nonce               string         `json:"nonce"`
	ServerID            string         `json:"server_id"`
	ServerDomain        string         `json:"server_domain"`
	FederationType      FederationType `json:"federation_type"`
	ServerEphemeralKey  EphemeralKey   `json:"server_ephemeral_key"`
	ServerIdentityProof FederationProof `json:"server_identity_proof"`
	DomainProof         DomainProof    `json:"domain_proof"`
	Capabilities        Capabilities   `json:"capabilities"`
	ServerSignature     string         `json:"server_signature"`
}

// FederationProof is the abbreviated identity proof used in federation
// init/response messages.
type FederationProof struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// DomainProof is one of the domain ownership verification methods accepted
// in a federation handshake (HANDSHAKE.md §5.3).
type DomainProof struct {
	// Method is one of "dns-txt", "certificate", "well-known".
	Method string `json:"method"`
	// Data is the verification payload, format determined by Method.
	Data string `json:"data"`
}

// Initiator drives the side of a federation handshake that opens the
// connection. Symmetric to handshake.Client but uses ServerInit and exposes
// federation-specific fields (server_domain, domain_proof).
type Initiator struct {
	suite        crypto.Suite
	store        keys.Store
	localDomain  string
	federation   FederationType
	ephemeralPub []byte
	ephemeralPriv []byte
}

// NewInitiator returns a federation initiator. localDomain is the domain
// this server represents.
func NewInitiator(suite crypto.Suite, store keys.Store, localDomain string, fed FederationType) *Initiator {
	return &Initiator{
		suite:       suite,
		store:       store,
		localDomain: localDomain,
		federation:  fed,
	}
}

// Init produces the message 1 (init/server) bytes.
//
// TODO(HANDSHAKE.md §5.2): implement.
func (i *Initiator) Init() ([]byte, error) {
	_ = i
	return nil, nil
}

// OnResponse processes message 2 and returns the confirm bytes plus a
// partially initialized session.
//
// TODO(HANDSHAKE.md §5.4 – §5.5): implement.
func (i *Initiator) OnResponse(data []byte) ([]byte, *session.Session, error) {
	_, _ = i, data
	return nil, nil, nil
}

// OnAccepted finalizes the federation session.
//
// TODO(HANDSHAKE.md §5.6): implement.
func (i *Initiator) OnAccepted(data []byte, sess *session.Session) error {
	_, _, _ = i, data, sess
	return nil
}

// Erase wipes initiator state.
func (i *Initiator) Erase() {
	if i == nil {
		return
	}
	crypto.Zeroize(i.ephemeralPriv)
	i.ephemeralPriv = nil
}

// Responder drives the receiving side of a federation handshake.
//
// Collision rule: when two federation servers simultaneously initiate
// handshakes to each other, the session whose session_id sorts lower
// lexicographically is abandoned (SESSION.md §2.5.2). This rule is enforced
// by the responder during OnInit when it detects an existing inbound
// session for the same peer domain.
type Responder struct {
	suite       crypto.Suite
	store       keys.Store
	localDomain string
	policy      Policy
}

// NewResponder constructs a federation responder.
func NewResponder(suite crypto.Suite, store keys.Store, localDomain string, policy Policy) *Responder {
	return &Responder{
		suite:       suite,
		store:       store,
		localDomain: localDomain,
		policy:      policy,
	}
}

// OnInit processes a federation init and returns the response bytes.
//
// TODO(HANDSHAKE.md §5.4): implement, including domain verification per
// §5.3 and the collision-resolution rule per SESSION.md §2.5.2.
func (r *Responder) OnInit(data []byte) ([]byte, error) {
	_, _ = r, data
	return nil, nil
}

// OnConfirm processes message 3 and returns the accepted bytes and session.
//
// TODO(HANDSHAKE.md §5.5 – §5.6): implement.
func (r *Responder) OnConfirm(data []byte) ([]byte, *session.Session, error) {
	_, _ = r, data
	return nil, nil, nil
}
