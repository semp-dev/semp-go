package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"semp.dev/semp-go/clockskew"
	"semp.dev/semp-go/crypto"
)

// MaxTicketLifetime is the upper bound on a resumption ticket's
// expires_at relative to its issuance time, per HANDSHAKE.md §2.8.4
// and SESSION.md §2.7. Issuers MUST cap any longer requested
// expires_at to this value; openers MUST reject tickets whose stored
// expires_at exceeds (issued_at + MaxTicketLifetime + a grace
// margin).
const MaxTicketLifetime = 7 * 24 * time.Hour

// TicketIDLen is the length in bytes of the cleartext ticket
// identifier prefix used by stateless tickets to key the
// consumed-ticket cache. 16 random bytes; collision probability
// 2^-64 per ticket-id is negligible at any realistic issuance rate.
const TicketIDLen = 16

// TicketIssuer issues, opens, and consumes opaque resumption tickets
// per SESSION.md §2.7 and HANDSHAKE.md §2.8. Implementations may be
// stateful (server-held table of ticket-id -> ticket payload) or
// stateless (AEAD-wrapped self-contained ticket bytes). The wire
// format is opaque to the client; only the issuing server can open a
// ticket it produced.
//
// All methods are safe for concurrent use.
type TicketIssuer interface {
	// Issue produces an opaque ticket binding identity and
	// resumptionSecret to the given expiry. expiresAt is clamped to
	// at most MaxTicketLifetime in the future.
	Issue(ctx context.Context, identity string, resumptionSecret []byte, expiresAt time.Time) ([]byte, error)

	// Open recovers the bound identity, resumption secret, and
	// expires_at from a ticket. Returns an error if the ticket is
	// corrupt, expired, or already consumed (ErrTicketUnknown,
	// ErrTicketExpired, or ErrTicketConsumed).
	Open(ctx context.Context, ticket []byte, now time.Time) (identity string, resumptionSecret []byte, expiresAt time.Time, err error)

	// Consume marks a ticket as consumed so it cannot be reused.
	// Single-use enforcement per SESSION.md §2.7.
	Consume(ctx context.Context, ticket []byte) error
}

// ErrTicketUnknown is returned when a presented ticket cannot be
// opened: corrupt, decrypted-payload-malformed, or (for stateful
// implementations) not in the table.
var ErrTicketUnknown = errors.New("session: ticket unknown or corrupt")

// ErrTicketExpired is returned when a presented ticket's expires_at
// is in the past (subject to clock-skew tolerance applied by the
// caller; the issuer itself does strict expiry).
var ErrTicketExpired = errors.New("session: ticket expired")

// ErrTicketConsumed is returned when a presented ticket has already
// been recorded in the consumed-ticket cache.
var ErrTicketConsumed = errors.New("session: ticket already consumed")

// StatelessTicketIssuer is a self-contained ticket implementation per
// SESSION.md §2.7 second bullet. The ticket value is an AEAD encryption
// of {identity, K_resumption, expires_at} under a server-held
// ticket-encryption key, prefixed with a random ticket-id used to key
// the consumed-ticket cache.
//
// Wire format of one ticket (raw bytes, before base64 in the wire
// message):
//
//	|--- 16 bytes ---|--- 12 bytes ---|----------- ciphertext+tag -----------|
//	| ticket_id      | aead_nonce     | AEAD(payload, AAD=ticket_id)         |
//
// payload is JSON: {"identity":"...","resumption":"<base64 32B>","expires_at":"<RFC3339>"}.
// AEAD is ChaCha20-Poly1305 with a 12-byte random nonce per ticket.
// Birthday collision on the nonce occurs at ~2^48 tickets per key;
// callers MUST rotate TicketKey at least quarterly per SESSION.md §2.7.
type StatelessTicketIssuer struct {
	aead     crypto.AEAD
	keyBytes []byte // 32 bytes; the server's ticket-encryption key

	consumedMu sync.Mutex
	consumed   map[[TicketIDLen]byte]time.Time // ticket-id -> expires_at
}

// NewStatelessTicketIssuer constructs a stateless ticket issuer
// backed by aead and ticketKey. ticketKey MUST be 32 bytes from a
// CSPRNG and SHOULD be rotated at least quarterly per SESSION.md
// §2.7. The returned issuer is safe for concurrent use.
func NewStatelessTicketIssuer(aead crypto.AEAD, ticketKey []byte) (*StatelessTicketIssuer, error) {
	if aead == nil {
		return nil, errors.New("session: nil aead")
	}
	if len(ticketKey) != aead.KeySize() {
		return nil, fmt.Errorf("session: ticket key length %d, want %d", len(ticketKey), aead.KeySize())
	}
	return &StatelessTicketIssuer{
		aead:     aead,
		keyBytes: append([]byte(nil), ticketKey...),
		consumed: map[[TicketIDLen]byte]time.Time{},
	}, nil
}

// statelessPayload is the structured plaintext bound inside the
// ticket. Stored in JSON for forward-compatible field additions; the
// server is the only party that ever marshals or unmarshals it.
type statelessPayload struct {
	Identity   string    `json:"identity"`
	Resumption string    `json:"resumption"` // base64 32 bytes
	ExpiresAt  time.Time `json:"expires_at"`
}

// Issue implements TicketIssuer.
func (s *StatelessTicketIssuer) Issue(_ context.Context, identity string, resumptionSecret []byte, expiresAt time.Time) ([]byte, error) {
	if identity == "" {
		return nil, errors.New("session: empty identity")
	}
	if len(resumptionSecret) == 0 {
		return nil, errors.New("session: empty resumption secret")
	}
	if expiresAt.IsZero() {
		return nil, errors.New("session: zero expires_at")
	}
	now := time.Now().UTC()
	maxExpiry := now.Add(MaxTicketLifetime)
	if expiresAt.After(maxExpiry) {
		expiresAt = maxExpiry
	}
	payload := statelessPayload{
		Identity:   identity,
		Resumption: base64.StdEncoding.EncodeToString(resumptionSecret),
		ExpiresAt:  expiresAt.UTC(),
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("session: marshal ticket payload: %w", err)
	}
	ticketID := make([]byte, TicketIDLen)
	if _, err := rand.Read(ticketID); err != nil {
		return nil, fmt.Errorf("session: ticket id rand: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("session: ticket nonce rand: %w", err)
	}
	ct, err := s.aead.Seal(s.keyBytes, nonce, plaintext, ticketID)
	if err != nil {
		return nil, fmt.Errorf("session: seal ticket: %w", err)
	}
	out := make([]byte, 0, TicketIDLen+len(nonce)+len(ct))
	out = append(out, ticketID...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open implements TicketIssuer. Returns the bound identity,
// resumption secret, and expires_at on success; ErrTicketUnknown,
// ErrTicketExpired, or ErrTicketConsumed on failure.
func (s *StatelessTicketIssuer) Open(_ context.Context, ticket []byte, now time.Time) (string, []byte, time.Time, error) {
	nonceLen := s.aead.NonceSize()
	if len(ticket) < TicketIDLen+nonceLen+s.aead.Overhead() {
		return "", nil, time.Time{}, ErrTicketUnknown
	}
	var ticketID [TicketIDLen]byte
	copy(ticketID[:], ticket[:TicketIDLen])
	if s.isConsumed(ticketID, now) {
		return "", nil, time.Time{}, ErrTicketConsumed
	}
	nonce := ticket[TicketIDLen : TicketIDLen+nonceLen]
	ct := ticket[TicketIDLen+nonceLen:]
	plaintext, err := s.aead.Open(s.keyBytes, nonce, ct, ticketID[:])
	if err != nil {
		// AEAD failure: ticket is corrupt or was issued under a
		// different key (post-rotation). Caller maps to
		// resumption_failed.
		return "", nil, time.Time{}, ErrTicketUnknown
	}
	var p statelessPayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return "", nil, time.Time{}, ErrTicketUnknown
	}
	if p.ExpiresAt.IsZero() {
		return "", nil, time.Time{}, ErrTicketUnknown
	}
	// The ticket was issued by the server (possibly a peer server in a
	// federation handshake) on its own clock. CONFORMANCE.md §9.3.1
	// requires uniform tolerance on every "valid until T" timestamp;
	// applying the Default grace lets a freshly-presented ticket
	// survive up to 15 minutes of clock skew before the verifier
	// rejects it as expired.
	if clockskew.CheckExpiry(p.ExpiresAt, now, clockskew.Default()) != nil {
		return "", nil, time.Time{}, ErrTicketExpired
	}
	resumption, err := base64.StdEncoding.DecodeString(p.Resumption)
	if err != nil {
		return "", nil, time.Time{}, ErrTicketUnknown
	}
	return p.Identity, resumption, p.ExpiresAt, nil
}

// Consume marks the ticket's identifier as consumed in the in-memory
// cache. The cache entry is retained until the ticket's expires_at
// passes; the periodic sweep in pruneConsumed removes stale entries.
func (s *StatelessTicketIssuer) Consume(_ context.Context, ticket []byte) error {
	if len(ticket) < TicketIDLen {
		return ErrTicketUnknown
	}
	var ticketID [TicketIDLen]byte
	copy(ticketID[:], ticket[:TicketIDLen])
	// The expires_at we record is best-effort: we re-derive it by
	// opening the ticket. If the ticket is corrupt at consume time
	// we still record an entry with a one-week TTL so it cannot be
	// retried.
	expires := time.Now().UTC().Add(MaxTicketLifetime)
	if _, _, exp, err := s.Open(context.Background(), ticket, time.Now().UTC()); err == nil {
		expires = exp
	}
	s.consumedMu.Lock()
	defer s.consumedMu.Unlock()
	s.consumed[ticketID] = expires
	return nil
}

// PruneConsumed removes consumed-ticket cache entries whose recorded
// expires_at has passed. Operators SHOULD call this periodically to
// bound memory.
func (s *StatelessTicketIssuer) PruneConsumed(now time.Time) {
	s.consumedMu.Lock()
	defer s.consumedMu.Unlock()
	for id, exp := range s.consumed {
		if now.After(exp) {
			delete(s.consumed, id)
		}
	}
}

// isConsumed reports whether ticketID is in the consumed cache. It
// also opportunistically prunes the entry if the recorded expires_at
// has passed.
func (s *StatelessTicketIssuer) isConsumed(ticketID [TicketIDLen]byte, now time.Time) bool {
	s.consumedMu.Lock()
	defer s.consumedMu.Unlock()
	exp, ok := s.consumed[ticketID]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(s.consumed, ticketID)
		return false
	}
	return true
}
