package test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/transport/ws"
)

// TestSEMPKeysVerifierAcceptsSignedResponse drives a full SEMP_KEYS
// round trip through a live inboxd.Server and verifies the response
// with keys.Verifier. The inboxd loop now attaches a domain signature
// to every user record AND a response-level origin_signature to each
// result, so the verifier accepts every returned key without
// `AllowUnsignedRecords`.
func TestSEMPKeysVerifierAcceptsSignedResponse(t *testing.T) {
	const (
		seed   = "test-keys-verify"
		domain = "example.com"
		alice  = "alice@example.com"
		bob    = "bob@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice, bob})
	defer srv.close()

	conn := openClientSession(t, suite, srv, seed, domain, alice)
	defer conn.Close()

	fetcher := keys.NewFetcher(conn)
	req := keys.NewRequest("verify-local", []string{bob})
	resp, err := fetcher.FetchKeys(context.Background(), req)
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}

	if len(resp.Results) != 1 || resp.Results[0].Status != keys.StatusFound {
		t.Fatalf("expected one found result, got %+v", resp.Results)
	}
	if resp.Results[0].OriginSignature == nil {
		t.Error("inboxd did not populate OriginSignature on the returned result")
	}
	for _, rec := range resp.Results[0].UserKeys {
		if len(rec.Signatures) == 0 {
			t.Errorf("user record %s has no signatures", rec.KeyID)
		}
	}

	verifier := &keys.Verifier{Suite: suite}
	if err := verifier.Verify(resp); err != nil {
		t.Errorf("verifier rejected a legitimate signed response: %v", err)
	}
}

// TestSEMPKeysVerifierRejectsTamperedResponse confirms the verifier
// catches a man-in-the-middle who swaps the recipient's encryption
// public key between the server signing the response and the client
// reading it.
func TestSEMPKeysVerifierRejectsTamperedResponse(t *testing.T) {
	const (
		seed   = "test-keys-tampered"
		domain = "example.com"
		alice  = "alice@example.com"
		bob    = "bob@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice, bob})
	defer srv.close()

	conn := openClientSession(t, suite, srv, seed, domain, alice)
	defer conn.Close()

	fetcher := keys.NewFetcher(conn)
	resp, err := fetcher.FetchKeys(context.Background(), keys.NewRequest("tamper", []string{bob}))
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}

	// Swap bob's encryption public key to a random attacker-chosen
	// value. Both the per-record signature and the response-level
	// origin_signature must fail as a result — the verifier catches
	// the per-record signature first.
	bobEnc := resp.Results[0].UserKeys[0]
	attackerPub, _, _ := suite.KEM().GenerateKeyPair()
	bobEnc.PublicKey = base64.StdEncoding.EncodeToString(attackerPub)

	verifier := &keys.Verifier{Suite: suite}
	if err := verifier.Verify(resp); err == nil {
		t.Error("verifier accepted a response with a tampered user public key")
	}
}

// TestSEMPKeysVerifierRejectsTamperedOriginSignature confirms the
// verifier catches a home server that drops the per-record
// signature and crafts its own origin_signature using a DIFFERENT
// domain key than the one published in the result — the classic
// "substituted domain key" attack on CLIENT.md §5.4.5.
func TestSEMPKeysVerifierRejectsTamperedOriginSignature(t *testing.T) {
	const (
		seed   = "test-keys-forged-origin"
		domain = "example.com"
		alice  = "alice@example.com"
		bob    = "bob@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice, bob})
	defer srv.close()

	conn := openClientSession(t, suite, srv, seed, domain, alice)
	defer conn.Close()

	fetcher := keys.NewFetcher(conn)
	resp, err := fetcher.FetchKeys(context.Background(), keys.NewRequest("forge", []string{bob}))
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}

	// Swap the DomainKey for an attacker-controlled one. The
	// OriginSignature was produced by the REAL domain key, so
	// verifying it against the attacker's key must fail.
	attackerPub, _, _ := suite.Signer().GenerateKeyPair()
	resp.Results[0].DomainKey.PublicKey = base64.StdEncoding.EncodeToString(attackerPub)

	verifier := &keys.Verifier{Suite: suite}
	if err := verifier.Verify(resp); err == nil {
		t.Error("verifier accepted a response with a substituted domain key")
	}
}

// openClientSession is a small helper that performs a client
// handshake against srv as `identity` and returns the live
// transport.Conn. Used by the verifier integration tests to avoid
// duplicating the handshake boilerplate.
func openClientSession(t *testing.T, suite crypto.Suite, srv *testServer, seed, domain, identity string) connCloser {
	t.Helper()
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srv.wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	store := newClientStore(t, seed, domain, identity, srv.store)
	identityFP := keys.Compute(mustIdentityPub(seed, identity))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      identity,
		IdentityKeyID: identityFP,
		ServerDomain:  domain,
	})
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	if _, err := handshake.RunClient(hsCtx, conn, cli); err != nil {
		t.Fatalf("RunClient: %v", err)
	}
	return conn
}

// connCloser is a tiny alias for the subset of transport.Conn the
// verifier tests need. Kept minimal so the helper doesn't force
// callers to import transport directly.
type connCloser interface {
	Send(context.Context, []byte) error
	Recv(context.Context) ([]byte, error)
	Close() error
}
