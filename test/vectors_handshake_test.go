package test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/handshake"
)

// Spec vectors for the handshake layer (VECTORS.md §§4.1, 4.2, 5.1).
// These verify that an implementation produces byte-for-byte identical
// outputs for the canonical inputs in the specification, which is the
// gating criterion for cross-implementation interop.

// vectorPoWPrefix is the raw 16-byte PoW prefix used by VECTORS.md §4.1
// and §4.2.
var vectorPoWPrefix = mustHex("4a8f2c1d3b5e7a9f0d6c8b4e2a1f3d5c")

const (
	vectorPoWChallengeID = "01JTEST22222222222222222222"

	// Vector §4.1: valid solution for difficulty 16.
	vectorPoWValidNonceB64 = "AAAAAAAArbc=" // base64(0x000000000000adb7)
	vectorPoWValidHashHex  = "0000cfa08ac13df837194fecda38add1267f3682fc7981cfab886d7c7c00caf4"

	// Vector §4.2: insufficient solution (only 7 leading zero bits).
	vectorPoWFailNonceB64 = "AAAAAAAAAAE=" // base64(0x0000000000000001)
	vectorPoWFailHashHex  = "011599577d9ecb9005422686c7635d32eb2b2f7f1c8b3972ff102b497f9ae7c6"
)

// TestVectorPoWValidSolution corresponds to VECTORS.md §4.1.
//
// Steps:
//  1. Reconstruct the canonical preimage from prefix, challenge_id, and nonce.
//  2. Compute SHA-256.
//  3. Confirm the result matches the vector hash.
//  4. Confirm at least 16 leading zero bits.
//
// All four steps are exercised by handshake.VerifySolution.
func TestVectorPoWValidSolution(t *testing.T) {
	if err := handshake.VerifySolution(
		vectorPoWPrefix,
		vectorPoWChallengeID,
		vectorPoWValidNonceB64,
		vectorPoWValidHashHex,
		16,
	); err != nil {
		t.Fatalf("VerifySolution(valid): %v", err)
	}
}

// TestVectorPoWInsufficientDifficulty corresponds to VECTORS.md §4.2.
// The hash matches the preimage but only has 7 leading zero bits, so
// VerifySolution MUST reject it at difficulty 16.
func TestVectorPoWInsufficientDifficulty(t *testing.T) {
	err := handshake.VerifySolution(
		vectorPoWPrefix,
		vectorPoWChallengeID,
		vectorPoWFailNonceB64,
		vectorPoWFailHashHex,
		16,
	)
	if err == nil {
		t.Fatal("VerifySolution accepted a hash with only 7 leading zero bits")
	}

	// Sanity check: at difficulty 7 the same solution is valid.
	if err := handshake.VerifySolution(
		vectorPoWPrefix,
		vectorPoWChallengeID,
		vectorPoWFailNonceB64,
		vectorPoWFailHashHex,
		7,
	); err != nil {
		t.Errorf("VerifySolution(valid at difficulty 7): %v", err)
	}
}

// TestVectorPoWHashMismatch confirms that VerifySolution rejects a
// preimage/hash pair where the claimed hash does not match the recomputed
// hash, even if both have sufficient leading zero bits.
func TestVectorPoWHashMismatch(t *testing.T) {
	bogusHash := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := handshake.VerifySolution(
		vectorPoWPrefix,
		vectorPoWChallengeID,
		vectorPoWValidNonceB64,
		bogusHash,
		16,
	); err == nil {
		t.Error("VerifySolution accepted a hash that does not match the preimage")
	}
}

// TestVectorPoWLeadingZeroBits validates the LeadingZeroBits helper against
// the two vector hashes. Vector §4.1 yields exactly 16 leading zero bits;
// vector §4.2 yields 7.
func TestVectorPoWLeadingZeroBits(t *testing.T) {
	good := mustHex(vectorPoWValidHashHex)
	bad := mustHex(vectorPoWFailHashHex)
	if got := handshake.LeadingZeroBits(good); got < 16 {
		t.Errorf("LeadingZeroBits(valid) = %d, want >= 16", got)
	}
	if got := handshake.LeadingZeroBits(bad); got != 7 {
		t.Errorf("LeadingZeroBits(insufficient) = %d, want 7", got)
	}
}

// TestVectorConfirmationHash corresponds to VECTORS.md §5.1.
//
// The vector provides the canonical forms of message_1 and message_2 as
// raw byte strings. We feed them directly into ConfirmationHash and check
// the result against the published SHA-256 digest.
func TestVectorConfirmationHash(t *testing.T) {
	// Canonical form of message 1 (init/client) per the vector. Note the
	// extension field is present as `extensions:{}`.
	m1 := []byte(`{"capabilities":{"compression":["zstd","none"],"encryption_algorithms":["pq-kyber768-x25519","x25519-chacha20-poly1305"],"features":["groups","threads"]},"client_ephemeral_key":{"algorithm":"pq-kyber768-x25519","key":"Y2xpZW50LWVwaGVtZXJhbC1rZXk=","key_id":"client-eph-fp"},"extensions":{},"nonce":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=","party":"client","step":"init","transport":"websocket","type":"SEMP_HANDSHAKE","version":"1.0.0"}`)

	// Canonical form of message 2 (response/server). The signed
	// `server_signature` is present in this canonical form (the spec
	// computes the confirmation hash over the message AS RECEIVED on the
	// wire, including the populated signature).
	m2 := []byte(`{"client_nonce":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=","extensions":{},"negotiated":{"compression":"zstd","encryption_algorithm":"pq-kyber768-x25519","features":["groups","threads"]},"party":"server","server_ephemeral_key":{"algorithm":"pq-kyber768-x25519","key":"c2VydmVyLWVwaGVtZXJhbC1rZXk=","key_id":"server-eph-fp"},"server_identity_proof":{"domain":"example.com","key_id":"server-lt-fp","signature":"c2VydmVyLXNpZw=="},"server_nonce":"u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=","server_signature":"c2VydmVyLXNpZ25hdHVyZQ==","session_id":"01JTEST33333333333333333333","step":"response","type":"SEMP_HANDSHAKE","version":"1.0.0"}`)

	want := mustHex("81208e0db84224eef8a6bde1510f119e34e4b910d63bcbb01e1e40504e851ab1")
	got, err := handshake.ConfirmationHash(m1, m2)
	if err != nil {
		t.Fatalf("ConfirmationHash: %v", err)
	}
	if !bytesEqual(got, want) {
		t.Errorf("ConfirmationHash mismatch:\n  got  %s\n  want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// TestPoWSolverFindsValidVectorNonce uses SolveChallenge to find a nonce
// for the same prefix and challenge_id used in vector §4.1, then verifies
// the solution it produces. This is a sanity check that the solver agrees
// with the verifier — not a vector test, since the solver may pick a
// different nonce than the vector.
func TestPoWSolverFindsValidVectorNonce(t *testing.T) {
	nonce, hashHex, err := handshake.SolveChallenge(vectorPoWPrefix, vectorPoWChallengeID, 12, time.Now().Add(60*time.Second))
	if err != nil {
		t.Fatalf("SolveChallenge: %v", err)
	}
	if err := handshake.VerifySolution(vectorPoWPrefix, vectorPoWChallengeID, nonce, hashHex, 12); err != nil {
		t.Errorf("VerifySolution: %v", err)
	}
}
