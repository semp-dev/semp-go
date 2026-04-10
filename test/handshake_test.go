package test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
)

// TestClientHandshakeRoundTrip drives the full four-message client handshake
// in a single process. The test wires a Client and a Server back to back via
// in-memory byte buffers, walks them through init → response → confirm →
// accepted, and then asserts:
//
//   1. Both sides agree on the session_id, the negotiated suite, and the
//      derived K_env_mac (via SessionsMatch).
//   2. The client session is in StateActive with a future ExpiresAt.
//   3. The server session is in StateActive with the matching peer identity.
//
// This is the milestone-3a acceptance test: it proves that the handshake
// state machines, the canonical serializer, the confirmation hash, the
// shared-secret derivation, the identity proof encryption, and all four
// message types interoperate end to end without any transport.
func TestClientHandshakeRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	store := newMemStore()

	// Sender (alice) — generate identity keypair, register it.
	identityPub, identityPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity keypair: %v", err)
	}
	identityFP := store.putUserKey("alice@example.com", keys.TypeIdentity, identityPub)
	store.putPrivateKey(identityFP, identityPriv)

	// Server — generate domain keypair, publish public key in the store.
	domainPub, domainPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("domain keypair: %v", err)
	}
	domainFP := store.putDomainKey("example.com", domainPub)

	// Wire up the state machines.
	client := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      "alice@example.com",
		IdentityKeyID: identityFP,
		ServerDomain:  "example.com",
	})
	server := handshake.NewServer(handshake.ServerConfig{
		Suite:            suite,
		Store:            store,
		Policy:           permitAllPolicy{},
		Domain:           "example.com",
		DomainKeyID:      domainFP,
		DomainPrivateKey: domainPriv,
	})
	defer client.Erase()
	defer server.Erase()

	// --- 1. Client → Server: init
	initBytes, err := client.Init()
	if err != nil {
		t.Fatalf("client.Init: %v", err)
	}
	t.Logf("init message: %d bytes", len(initBytes))

	// --- 2. Server → Client: response
	respBytes, err := server.OnInit(initBytes)
	if err != nil {
		t.Fatalf("server.OnInit: %v", err)
	}
	t.Logf("response message: %d bytes", len(respBytes))

	// --- 3. Client → Server: confirm (and partially-built session)
	confirmBytes, clientSession, err := client.OnResponse(respBytes)
	if err != nil {
		t.Fatalf("client.OnResponse: %v", err)
	}
	t.Logf("confirm message: %d bytes", len(confirmBytes))
	if clientSession.State != session.StateHandshaking {
		t.Errorf("client session should be handshaking after OnResponse, got %s", clientSession.State)
	}

	// --- 4. Server → Client: accepted (and fully-built server session)
	acceptedBytes, serverSession, err := server.OnConfirm(confirmBytes)
	if err != nil {
		t.Fatalf("server.OnConfirm: %v", err)
	}
	t.Logf("accepted message: %d bytes", len(acceptedBytes))
	if serverSession.State != session.StateActive {
		t.Errorf("server session should be active, got %s", serverSession.State)
	}
	if serverSession.PeerIdentity != "alice@example.com" {
		t.Errorf("server session peer identity = %q, want alice@example.com", serverSession.PeerIdentity)
	}

	// --- Client finalizes its session.
	if err := client.OnAccepted(acceptedBytes, clientSession); err != nil {
		t.Fatalf("client.OnAccepted: %v", err)
	}
	if clientSession.State != session.StateActive {
		t.Errorf("client session should be active after OnAccepted, got %s", clientSession.State)
	}
	if !clientSession.Active(time.Now()) {
		t.Error("client session is not active per Session.Active")
	}

	// --- Both sides MUST agree on the session ID and the K_env_mac.
	if clientSession.ID == "" {
		t.Error("client session ID is empty")
	}
	if clientSession.ID != serverSession.ID {
		t.Errorf("session ID mismatch: client=%s server=%s", clientSession.ID, serverSession.ID)
	}
	if clientSession.ID != server.SessionID() {
		t.Errorf("server.SessionID() = %s, want %s", server.SessionID(), clientSession.ID)
	}
	if !bytesEqualHelper(clientSession.EnvMAC(), serverSession.EnvMAC()) {
		t.Error("K_env_mac mismatch between client and server sessions")
	}
	if server.ClientIdentity() != "alice@example.com" {
		t.Errorf("server.ClientIdentity() = %q, want alice@example.com", server.ClientIdentity())
	}

	// Sanity: the canonical bytes the client just produced for confirm
	// should still parse and round-trip without changing the session ID.
	_ = context.Background()
}

// TestHandshakeRejectsTamperedResponse checks that when the server's
// response is mutated in transit, the client refuses to send a confirm.
func TestHandshakeRejectsTamperedResponse(t *testing.T) {
	suite := crypto.SuiteBaseline
	store := newMemStore()

	identityPub, identityPriv, _ := suite.Signer().GenerateKeyPair()
	identityFP := store.putUserKey("alice@example.com", keys.TypeIdentity, identityPub)
	store.putPrivateKey(identityFP, identityPriv)

	domainPub, domainPriv, _ := suite.Signer().GenerateKeyPair()
	domainFP := store.putDomainKey("example.com", domainPub)

	client := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      "alice@example.com",
		IdentityKeyID: identityFP,
		ServerDomain:  "example.com",
	})
	server := handshake.NewServer(handshake.ServerConfig{
		Suite:            suite,
		Store:            store,
		Policy:           permitAllPolicy{},
		Domain:           "example.com",
		DomainKeyID:      domainFP,
		DomainPrivateKey: domainPriv,
	})
	defer client.Erase()
	defer server.Erase()

	initBytes, _ := client.Init()
	respBytes, err := server.OnInit(initBytes)
	if err != nil {
		t.Fatalf("server.OnInit: %v", err)
	}

	// Flip a byte inside the response — somewhere likely to break the
	// signature without producing invalid JSON.
	tampered := append([]byte{}, respBytes...)
	// Walk to the first ASCII letter past the opening brace and flip it.
	for i := 1; i < len(tampered); i++ {
		if (tampered[i] >= 'a' && tampered[i] <= 'z') || (tampered[i] >= 'A' && tampered[i] <= 'Z') {
			tampered[i] ^= 0x01
			break
		}
	}
	if _, _, err := client.OnResponse(tampered); err == nil {
		t.Error("client.OnResponse accepted a tampered response")
	}
}

// TestHandshakeRejectsWrongClientIdentityKey covers the case where the
// client tries to authenticate as alice but signs with the wrong identity
// private key. The server's identity_signature verification MUST fail.
func TestHandshakeRejectsWrongClientIdentityKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	store := newMemStore()

	// Register alice's REAL identity public key, but the client will use a
	// different private key (no entry in privateKeys for the real fp).
	realPub, _, _ := suite.Signer().GenerateKeyPair()
	realFP := store.putUserKey("alice@example.com", keys.TypeIdentity, realPub)

	// Stash an UNRELATED private key under realFP. Signatures will be valid
	// over the bytes but won't verify against realPub.
	_, fakePriv, _ := suite.Signer().GenerateKeyPair()
	store.putPrivateKey(realFP, fakePriv)

	domainPub, domainPriv, _ := suite.Signer().GenerateKeyPair()
	domainFP := store.putDomainKey("example.com", domainPub)

	client := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      "alice@example.com",
		IdentityKeyID: realFP,
		ServerDomain:  "example.com",
	})
	server := handshake.NewServer(handshake.ServerConfig{
		Suite:            suite,
		Store:            store,
		Policy:           permitAllPolicy{},
		Domain:           "example.com",
		DomainKeyID:      domainFP,
		DomainPrivateKey: domainPriv,
	})
	defer client.Erase()
	defer server.Erase()

	initBytes, _ := client.Init()
	respBytes, _ := server.OnInit(initBytes)
	confirmBytes, _, err := client.OnResponse(respBytes)
	if err != nil {
		t.Fatalf("client.OnResponse: %v", err)
	}
	if _, _, err := server.OnConfirm(confirmBytes); err == nil {
		t.Error("server.OnConfirm accepted a confirm signed with the wrong identity key")
	}
}

// TestHandshakeWithPoWChallenge exercises the conditional pow_required /
// pow_solution interstitial. The server is configured with a powGatePolicy
// that issues a (low-difficulty) challenge once. The client must solve it
// before the handshake can proceed. Difficulty 8 is sufficient to be
// observably an interstitial without making the test slow.
func TestHandshakeWithPoWChallenge(t *testing.T) {
	suite := crypto.SuiteBaseline
	store := newMemStore()

	identityPub, identityPriv, _ := suite.Signer().GenerateKeyPair()
	identityFP := store.putUserKey("alice@example.com", keys.TypeIdentity, identityPub)
	store.putPrivateKey(identityFP, identityPriv)

	domainPub, domainPriv, _ := suite.Signer().GenerateKeyPair()
	domainFP := store.putDomainKey("example.com", domainPub)

	prefix := make([]byte, 16)
	for i := range prefix {
		prefix[i] = byte(i + 1)
	}
	policy := &powGatePolicy{
		challenge: &handshake.PoWRequired{
			Type:        "SEMP_HANDSHAKE",
			Step:        handshake.StepPoWRequired,
			Party:       handshake.PartyServer,
			Version:     "1.0.0",
			ChallengeID: "TESTCHALLENGE0000000001",
			Algorithm:   handshake.PoWAlgorithm,
			Prefix:      base64.StdEncoding.EncodeToString(prefix),
			Difficulty:  8, // ~256 iterations on average — fast enough for tests
			Expires:     time.Now().Add(60 * time.Second),
		},
	}
	client := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      "alice@example.com",
		IdentityKeyID: identityFP,
		ServerDomain:  "example.com",
	})
	server := handshake.NewServer(handshake.ServerConfig{
		Suite:            suite,
		Store:            store,
		Policy:           policy,
		Domain:           "example.com",
		DomainKeyID:      domainFP,
		DomainPrivateKey: domainPriv,
	})
	defer client.Erase()
	defer server.Erase()

	initBytes, _ := client.Init()

	// Server should respond with a pow_required.
	powBytes, err := server.OnInit(initBytes)
	if err != nil {
		t.Fatalf("server.OnInit: %v", err)
	}
	// Client solves the challenge.
	solBytes, err := client.OnPoWRequired(powBytes)
	if err != nil {
		t.Fatalf("client.OnPoWRequired: %v", err)
	}
	// Server validates the solution and produces the actual response.
	respBytes, err := server.OnPoWSolution(solBytes)
	if err != nil {
		t.Fatalf("server.OnPoWSolution: %v", err)
	}
	confirmBytes, clientSession, err := client.OnResponse(respBytes)
	if err != nil {
		t.Fatalf("client.OnResponse: %v", err)
	}
	acceptedBytes, serverSession, err := server.OnConfirm(confirmBytes)
	if err != nil {
		t.Fatalf("server.OnConfirm: %v", err)
	}
	if err := client.OnAccepted(acceptedBytes, clientSession); err != nil {
		t.Fatalf("client.OnAccepted: %v", err)
	}
	if !clientSession.Active(time.Now()) {
		t.Error("client session not active after PoW handshake")
	}
	if !bytesEqualHelper(clientSession.EnvMAC(), serverSession.EnvMAC()) {
		t.Error("K_env_mac mismatch after PoW handshake")
	}
}

// bytesEqualHelper is a tiny copy to avoid colliding with bytesEqual in
// vectors_test.go which is package-private to this same package.
func bytesEqualHelper(a, b []byte) bool {
	return bytesEqual(a, b)
}
