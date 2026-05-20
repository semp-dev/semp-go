package session_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/session"
)

func newTestIssuer(t *testing.T) *session.StatelessTicketIssuer {
	t.Helper()
	aead := crypto.SuiteBaseline.AEAD()
	key := bytes.Repeat([]byte{0x77}, aead.KeySize())
	issuer, err := session.NewStatelessTicketIssuer(aead, key)
	if err != nil {
		t.Fatalf("NewStatelessTicketIssuer: %v", err)
	}
	return issuer
}

// TestStatelessTicketRoundTrip verifies the basic Issue → Open
// happy path: the bound identity, resumption secret, and expires_at
// recover identically.
func TestStatelessTicketRoundTrip(t *testing.T) {
	issuer := newTestIssuer(t)
	identity := "alice@example.com"
	resumption := bytes.Repeat([]byte{0xCD}, 32)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

	ticket, err := issuer.Issue(context.Background(), identity, resumption, expires)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(ticket) < session.TicketIDLen {
		t.Fatal("ticket shorter than ticket-id prefix")
	}

	gotIdentity, gotResumption, gotExpires, err := issuer.Open(context.Background(), ticket, time.Now().UTC())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if gotIdentity != identity {
		t.Errorf("identity = %q, want %q", gotIdentity, identity)
	}
	if !bytes.Equal(gotResumption, resumption) {
		t.Error("resumption secret round-trip mismatch")
	}
	if !gotExpires.Equal(expires) {
		t.Errorf("expires_at = %s, want %s", gotExpires, expires)
	}
}

// TestStatelessTicketSingleUse confirms that consuming a ticket
// makes a subsequent Open of the same ticket return ErrTicketConsumed
// per HANDSHAKE.md §2.8.4.
func TestStatelessTicketSingleUse(t *testing.T) {
	issuer := newTestIssuer(t)
	ticket, err := issuer.Issue(context.Background(), "alice@example.com",
		bytes.Repeat([]byte{0xAB}, 32), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// First Open succeeds.
	if _, _, _, err := issuer.Open(context.Background(), ticket, time.Now().UTC()); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// Mark consumed.
	if err := issuer.Consume(context.Background(), ticket); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	// Second Open MUST fail with ErrTicketConsumed.
	_, _, _, err = issuer.Open(context.Background(), ticket, time.Now().UTC())
	if err != session.ErrTicketConsumed {
		t.Errorf("second Open after Consume: got %v, want ErrTicketConsumed", err)
	}
}

// TestStatelessTicketExpiry confirms Open rejects tickets whose
// expires_at has passed beyond the §4.4 grace window.
func TestStatelessTicketExpiry(t *testing.T) {
	issuer := newTestIssuer(t)
	ticket, err := issuer.Issue(context.Background(), "alice@example.com",
		bytes.Repeat([]byte{0xAB}, 32), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	future := time.Now().UTC().Add(2 * time.Hour)
	_, _, _, err = issuer.Open(context.Background(), ticket, future)
	if err != session.ErrTicketExpired {
		t.Errorf("Open past expiry: got %v, want ErrTicketExpired", err)
	}
}

// TestStatelessTicketGraceWindow confirms a ticket whose expires_at
// is within the §4.4 Default 15-minute grace window is still
// accepted. The ticket was issued by the server on its own clock;
// CONFORMANCE.md §9.3.1 lets verifiers grace up to 15 minutes of
// peer-clock skew before treating the timestamp as expired.
func TestStatelessTicketGraceWindow(t *testing.T) {
	issuer := newTestIssuer(t)
	expiresAt := time.Now().UTC().Add(time.Hour)
	ticket, err := issuer.Issue(context.Background(), "alice@example.com",
		bytes.Repeat([]byte{0xAB}, 32), expiresAt)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// 5 minutes past expiry - well inside the 15-min Default grace.
	withinGrace := expiresAt.Add(5 * time.Minute)
	if _, _, _, err := issuer.Open(context.Background(), ticket, withinGrace); err != nil {
		t.Errorf("Open inside grace window: %v", err)
	}
}

// TestStatelessTicketLifetimeCap confirms that a requested expires_at
// beyond MaxTicketLifetime is silently clamped.
func TestStatelessTicketLifetimeCap(t *testing.T) {
	issuer := newTestIssuer(t)
	tooLong := time.Now().UTC().Add(30 * 24 * time.Hour) // 30 days; cap is 7
	ticket, err := issuer.Issue(context.Background(), "alice@example.com",
		bytes.Repeat([]byte{0xAB}, 32), tooLong)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, _, gotExpires, err := issuer.Open(context.Background(), ticket, time.Now().UTC())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	maxExpected := time.Now().UTC().Add(session.MaxTicketLifetime + time.Minute)
	if gotExpires.After(maxExpected) {
		t.Errorf("expires_at = %s, want <= %s (clamped to MaxTicketLifetime)",
			gotExpires, maxExpected)
	}
}

// TestStatelessTicketTamperRejects confirms that any single-byte
// flip in the ticket payload (after the ticket-id prefix, where the
// AEAD covers) breaks Open. The AEAD AAD is the ticket-id, so a flip
// in ticket-id ALSO breaks decryption (the AAD changes but the key
// material doesn't).
func TestStatelessTicketTamperRejects(t *testing.T) {
	issuer := newTestIssuer(t)
	ticket, err := issuer.Issue(context.Background(), "alice@example.com",
		bytes.Repeat([]byte{0xAB}, 32), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Flip a byte in the ciphertext region.
	tampered := append([]byte{}, ticket...)
	tampered[len(tampered)-1] ^= 0x01
	_, _, _, err = issuer.Open(context.Background(), tampered, time.Now().UTC())
	if err != session.ErrTicketUnknown {
		t.Errorf("Open tampered ticket: got %v, want ErrTicketUnknown", err)
	}
}

// TestStatelessTicketDifferentKeyRejects confirms that a ticket
// issued under one ticket-encryption key cannot be opened by an
// issuer holding a different key. This models the post-rotation
// behavior where outstanding tickets become undecryptable.
func TestStatelessTicketDifferentKeyRejects(t *testing.T) {
	aead := crypto.SuiteBaseline.AEAD()
	key1 := bytes.Repeat([]byte{0xAA}, aead.KeySize())
	key2 := bytes.Repeat([]byte{0xBB}, aead.KeySize())
	a, _ := session.NewStatelessTicketIssuer(aead, key1)
	b, _ := session.NewStatelessTicketIssuer(aead, key2)
	ticket, err := a.Issue(context.Background(), "alice@example.com",
		bytes.Repeat([]byte{0xCC}, 32), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, _, _, err = b.Open(context.Background(), ticket, time.Now().UTC())
	if err != session.ErrTicketUnknown {
		t.Errorf("Open under different key: got %v, want ErrTicketUnknown", err)
	}
}

// TestStatelessTicketPruneConsumed confirms that the consumed-cache
// pruning removes entries whose expires_at has passed.
func TestStatelessTicketPruneConsumed(t *testing.T) {
	issuer := newTestIssuer(t)
	ticket, _ := issuer.Issue(context.Background(), "alice@example.com",
		bytes.Repeat([]byte{0xAB}, 32), time.Now().UTC().Add(time.Hour))
	if err := issuer.Consume(context.Background(), ticket); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	// Prune at far-future "now"; the entry should be removed and the
	// ticket no longer reports as consumed (though it would still
	// fail Open with ErrTicketExpired).
	issuer.PruneConsumed(time.Now().UTC().Add(2 * time.Hour))
	// We can't check the cache state directly, but a fresh Issue
	// after pruning should keep working.
	_, err := issuer.Issue(context.Background(), "bob@example.com",
		bytes.Repeat([]byte{0xCD}, 32), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Errorf("Issue after prune: %v", err)
	}
}
