package test

import (
	"context"
	"errors"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/session"
)

// TestFederationHandshakeRoundTrip drives the full four-message federation
// handshake in a single process. Server A is the initiator, Server B the
// responder. The test wires both sides together via in-memory byte buffers
// and asserts:
//
//   1. Both sides agree on the session_id and the K_env_mac.
//   2. Both sessions end up in StateActive with role RoleFederation.
//   3. The peer domains are correctly recorded on each side.
//
// This is the milestone-3c acceptance test for the federation layer.
func TestFederationHandshakeRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline

	// Each server has its own keys.Store. We populate each store with the
	// OTHER server's domain public key, mirroring what discovery would do
	// in a real deployment.
	storeA := newMemStore()
	storeB := newMemStore()

	domainPubA, domainPrivA, _ := suite.Signer().GenerateKeyPair()
	domainPubB, domainPrivB, _ := suite.Signer().GenerateKeyPair()
	fpA := storeA.putDomainKey("a.example", domainPubA) // A knows its own (not strictly required)
	fpB := storeB.putDomainKey("b.example", domainPubB)

	// Cross-publish.
	storeA.putDomainKey("b.example", domainPubB)
	storeB.putDomainKey("a.example", domainPubA)

	initiator := handshake.NewInitiator(handshake.InitiatorConfig{
		Suite:                 suite,
		Store:                 storeA,
		LocalDomain:           "a.example",
		LocalDomainKeyID:      fpA,
		LocalDomainPrivateKey: domainPrivA,
		PeerDomain:            "b.example",
		DomainProof: handshake.DomainProof{
			Method: handshake.DomainVerifyTestTrust,
			Data:   "trust-me-im-a.example",
		},
	})
	responder := handshake.NewResponder(handshake.ResponderConfig{
		Suite:                 suite,
		Store:                 storeB,
		LocalDomain:           "b.example",
		LocalDomainKeyID:      fpB,
		LocalDomainPrivateKey: domainPrivB,
		Policy: handshake.FederationPolicy{
			MessageRetention: "7d",
			UserDiscovery:    "allowed",
			RelayAllowed:     true,
		},
		SessionTTL: 3600,
	})
	defer initiator.Erase()
	defer responder.Erase()

	// 1. Initiator → Responder: init
	initBytes, err := initiator.Init()
	if err != nil {
		t.Fatalf("initiator.Init: %v", err)
	}
	t.Logf("federation init: %d bytes", len(initBytes))

	// 2. Responder → Initiator: response
	respBytes, err := responder.OnInit(initBytes)
	if err != nil {
		t.Fatalf("responder.OnInit: %v", err)
	}
	t.Logf("federation response: %d bytes", len(respBytes))

	// 3. Initiator → Responder: confirm
	confirmBytes, sessA, err := initiator.OnResponse(respBytes)
	if err != nil {
		t.Fatalf("initiator.OnResponse: %v", err)
	}
	t.Logf("federation confirm: %d bytes", len(confirmBytes))
	if sessA.State != session.StateHandshaking {
		t.Errorf("initiator session should be handshaking after OnResponse, got %s", sessA.State)
	}
	if sessA.Role != session.RoleFederation {
		t.Errorf("initiator session role = %v, want RoleFederation", sessA.Role)
	}

	// 4. Responder → Initiator: accepted
	acceptedBytes, sessB, err := responder.OnConfirm(confirmBytes)
	if err != nil {
		t.Fatalf("responder.OnConfirm: %v", err)
	}
	t.Logf("federation accepted: %d bytes", len(acceptedBytes))
	if sessB.State != session.StateActive {
		t.Errorf("responder session should be active, got %s", sessB.State)
	}
	if sessB.PeerIdentity != "a.example" {
		t.Errorf("responder peer identity = %q, want a.example", sessB.PeerIdentity)
	}

	// Initiator finalizes.
	if err := initiator.OnAccepted(acceptedBytes, sessA); err != nil {
		t.Fatalf("initiator.OnAccepted: %v", err)
	}
	if sessA.State != session.StateActive {
		t.Errorf("initiator session should be active after OnAccepted, got %s", sessA.State)
	}
	if !sessA.Active(time.Now()) {
		t.Error("initiator session is not active per Session.Active")
	}

	// Both sides MUST agree on session_id and K_env_mac.
	if sessA.ID != sessB.ID {
		t.Errorf("session ID mismatch: A=%s B=%s", sessA.ID, sessB.ID)
	}
	if sessA.ID != initiator.SessionID() {
		t.Errorf("initiator.SessionID() = %s, want %s", initiator.SessionID(), sessA.ID)
	}
	if sessA.ID != responder.SessionID() {
		t.Errorf("responder.SessionID() = %s, want %s", responder.SessionID(), sessA.ID)
	}
	if !bytesEqual(sessA.EnvMAC(), sessB.EnvMAC()) {
		t.Error("K_env_mac mismatch between initiator and responder federation sessions")
	}
	if sessA.PeerIdentity != "b.example" {
		t.Errorf("initiator peer identity = %q, want b.example", sessA.PeerIdentity)
	}

	// Sessions should have the configured TTL.
	if sessA.TTL != time.Hour {
		t.Errorf("initiator TTL = %s, want 1h", sessA.TTL)
	}
	if sessB.TTL != time.Hour {
		t.Errorf("responder TTL = %s, want 1h", sessB.TTL)
	}
}

// rejectingDomainVerifier always fails domain verification with a fixed
// error. Used to exercise the rejection path in OnInit.
type rejectingDomainVerifier struct{}

func (rejectingDomainVerifier) Verify(_ context.Context, _ string, _ handshake.DomainProof, _ string) error {
	return errors.New("test: rejecting all domain proofs")
}

// TestFederationRejectsBadDomainProof confirms that a Responder configured
// with a rejecting DomainVerifier refuses to send a response when the
// initiator's DomainProof fails verification.
func TestFederationRejectsBadDomainProof(t *testing.T) {
	suite := crypto.SuiteBaseline
	storeA := newMemStore()
	storeB := newMemStore()
	domainPubA, domainPrivA, _ := suite.Signer().GenerateKeyPair()
	domainPubB, domainPrivB, _ := suite.Signer().GenerateKeyPair()
	fpA := storeA.putDomainKey("a.example", domainPubA)
	fpB := storeB.putDomainKey("b.example", domainPubB)
	storeA.putDomainKey("b.example", domainPubB)
	storeB.putDomainKey("a.example", domainPubA)

	initiator := handshake.NewInitiator(handshake.InitiatorConfig{
		Suite:                 suite,
		Store:                 storeA,
		LocalDomain:           "a.example",
		LocalDomainKeyID:      fpA,
		LocalDomainPrivateKey: domainPrivA,
		PeerDomain:            "b.example",
		DomainProof: handshake.DomainProof{
			Method: "dns-txt",
			Data:   "obviously-bad",
		},
	})
	responder := handshake.NewResponder(handshake.ResponderConfig{
		Suite:                 suite,
		Store:                 storeB,
		Verifier:              rejectingDomainVerifier{},
		LocalDomain:           "b.example",
		LocalDomainKeyID:      fpB,
		LocalDomainPrivateKey: domainPrivB,
	})
	defer initiator.Erase()
	defer responder.Erase()

	initBytes, err := initiator.Init()
	if err != nil {
		t.Fatalf("initiator.Init: %v", err)
	}
	if _, err := responder.OnInit(initBytes); err == nil {
		t.Error("responder.OnInit accepted a bad domain proof")
	}
}

// rejectingPolicyAcceptor refuses every policy and surfaces the reason on
// confirm.
func rejectingPolicyAcceptor(_ handshake.FederationPolicy) error {
	return errors.New("test: refusing all policies")
}

// TestFederationInitiatorRejectsPolicy confirms that when the initiator's
// PolicyAcceptor refuses the responder's policy, the responder receives a
// confirm with `accepted: false` and OnConfirm returns an error rather than
// establishing a session.
func TestFederationInitiatorRejectsPolicy(t *testing.T) {
	suite := crypto.SuiteBaseline
	storeA := newMemStore()
	storeB := newMemStore()
	domainPubA, domainPrivA, _ := suite.Signer().GenerateKeyPair()
	domainPubB, domainPrivB, _ := suite.Signer().GenerateKeyPair()
	fpA := storeA.putDomainKey("a.example", domainPubA)
	fpB := storeB.putDomainKey("b.example", domainPubB)
	storeA.putDomainKey("b.example", domainPubB)
	storeB.putDomainKey("a.example", domainPubA)

	initiator := handshake.NewInitiator(handshake.InitiatorConfig{
		Suite:                 suite,
		Store:                 storeA,
		LocalDomain:           "a.example",
		LocalDomainKeyID:      fpA,
		LocalDomainPrivateKey: domainPrivA,
		PeerDomain:            "b.example",
		DomainProof:           handshake.DomainProof{Method: handshake.DomainVerifyTestTrust, Data: "ok"},
		PolicyAcceptor:        rejectingPolicyAcceptor,
	})
	responder := handshake.NewResponder(handshake.ResponderConfig{
		Suite:                 suite,
		Store:                 storeB,
		LocalDomain:           "b.example",
		LocalDomainKeyID:      fpB,
		LocalDomainPrivateKey: domainPrivB,
		Policy: handshake.FederationPolicy{
			MessageRetention: "30d",
			UserDiscovery:    "denied",
			RelayAllowed:     false,
		},
	})
	defer initiator.Erase()
	defer responder.Erase()

	initBytes, _ := initiator.Init()
	respBytes, err := responder.OnInit(initBytes)
	if err != nil {
		t.Fatalf("responder.OnInit: %v", err)
	}
	confirmBytes, _, err := initiator.OnResponse(respBytes)
	if err != nil {
		t.Fatalf("initiator.OnResponse: %v", err)
	}
	if _, _, err := responder.OnConfirm(confirmBytes); err == nil {
		t.Error("responder.OnConfirm accepted a confirm where the initiator declined the policy")
	}
}

// TestResolveCollision validates the SESSION.md §2.5.2 simultaneous
// handshake collision rule. Both peers, given the same pair of session IDs,
// must independently agree on the same winner — the lexicographically
// HIGHER ID. The lower ID is abandoned.
func TestResolveCollision(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		// Standard case: distinct IDs, higher wins.
		{"01J0000000000000000000000A", "01J0000000000000000000000B", "01J0000000000000000000000B"},
		{"01J0000000000000000000000B", "01J0000000000000000000000A", "01J0000000000000000000000B"},
		// All-zero vs. all-one prefix.
		{"00000000000000000000000000", "11111111111111111111111111", "11111111111111111111111111"},
		// Equal IDs (should not occur in practice but the rule must be
		// total — ResolveCollision returns the second arg as a tie-break).
		{"AAAA", "AAAA", "AAAA"},
	}
	for _, tc := range cases {
		got := handshake.ResolveCollision(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("ResolveCollision(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
		// Symmetric: both peers (running ResolveCollision with their args
		// in opposite order) MUST agree.
		other := handshake.ResolveCollision(tc.b, tc.a)
		if other != got {
			t.Errorf("ResolveCollision asymmetric: (%q,%q)=%q vs (%q,%q)=%q",
				tc.a, tc.b, got, tc.b, tc.a, other)
		}
	}
}

// TestFederationRejectsTamperedResponse — sanity check that mutating the
// responder's signed response causes the initiator to refuse the confirm.
func TestFederationRejectsTamperedResponse(t *testing.T) {
	suite := crypto.SuiteBaseline
	storeA := newMemStore()
	storeB := newMemStore()
	domainPubA, domainPrivA, _ := suite.Signer().GenerateKeyPair()
	domainPubB, domainPrivB, _ := suite.Signer().GenerateKeyPair()
	fpA := storeA.putDomainKey("a.example", domainPubA)
	fpB := storeB.putDomainKey("b.example", domainPubB)
	storeA.putDomainKey("b.example", domainPubB)
	storeB.putDomainKey("a.example", domainPubA)

	initiator := handshake.NewInitiator(handshake.InitiatorConfig{
		Suite:                 suite,
		Store:                 storeA,
		LocalDomain:           "a.example",
		LocalDomainKeyID:      fpA,
		LocalDomainPrivateKey: domainPrivA,
		PeerDomain:            "b.example",
		DomainProof:           handshake.DomainProof{Method: handshake.DomainVerifyTestTrust, Data: "ok"},
	})
	responder := handshake.NewResponder(handshake.ResponderConfig{
		Suite:                 suite,
		Store:                 storeB,
		LocalDomain:           "b.example",
		LocalDomainKeyID:      fpB,
		LocalDomainPrivateKey: domainPrivB,
	})
	defer initiator.Erase()
	defer responder.Erase()

	initBytes, _ := initiator.Init()
	respBytes, err := responder.OnInit(initBytes)
	if err != nil {
		t.Fatalf("responder.OnInit: %v", err)
	}
	tampered := append([]byte{}, respBytes...)
	for i := 1; i < len(tampered); i++ {
		if (tampered[i] >= 'a' && tampered[i] <= 'z') || (tampered[i] >= 'A' && tampered[i] <= 'Z') {
			tampered[i] ^= 0x01
			break
		}
	}
	if _, _, err := initiator.OnResponse(tampered); err == nil {
		t.Error("initiator.OnResponse accepted a tampered federation response")
	}
}
