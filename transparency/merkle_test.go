package transparency_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/transparency"
)

// buildTree returns the Merkle root and per-leaf inclusion proof
// data for a list of leaf hashes, using the same RFC 6962 hashing
// the production code expects. Used to seed the verification tests.
func buildTree(t *testing.T, leaves [][32]byte) (root [32]byte, allInclusionProofs []transparency.InclusionProof) {
	t.Helper()
	if len(leaves) == 0 {
		return [32]byte{}, nil
	}
	// Compute root via straightforward recursion.
	root = computeRoot(leaves)
	// Build an inclusion proof for every leaf.
	proofs := make([]transparency.InclusionProof, len(leaves))
	for i := range leaves {
		path := computeInclusionPath(leaves, int64(i))
		proofs[i] = transparency.InclusionProof{
			LogSize:   int64(len(leaves)),
			LeafHash:  base64.StdEncoding.EncodeToString(leaves[i][:]),
			LeafIndex: int64(i),
			Path:      hashesToBase64(path),
		}
	}
	return root, proofs
}

func computeRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := transparency.LargestPowerOfTwoLessThan(int64(len(leaves)))
	left := computeRoot(leaves[:k])
	right := computeRoot(leaves[k:])
	return transparency.HashInterior(left, right)
}

func computeInclusionPath(leaves [][32]byte, i int64) [][32]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := transparency.LargestPowerOfTwoLessThan(int64(len(leaves)))
	if i < k {
		return append(
			computeInclusionPath(leaves[:k], i),
			computeRoot(leaves[k:]),
		)
	}
	return append(
		computeInclusionPath(leaves[k:], i-k),
		computeRoot(leaves[:k]),
	)
}

func computeConsistencyPath(leaves [][32]byte, m, n int64) [][32]byte {
	// RFC 6962 SUBPROOF(m, D[n], true). leaves represents D[n], the
	// later tree. m is the older tree size; n is the later tree size.
	// Reuses the package-level subproof helper from log.go.
	return transparency.Subproof(int(m), leaves[:n], true)
}


func hashesToBase64(hs [][32]byte) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = base64.StdEncoding.EncodeToString(h[:])
	}
	return out
}

func makeLeaves(n int) [][32]byte {
	leaves := make([][32]byte, n)
	for i := 0; i < n; i++ {
		body := []byte{byte(i)}
		// Match the leaf hashing used by HashLeaf. The exact JSON
		// shape doesn't matter for the math; only that the leaf
		// hash is a 32-byte value derived from a leaf-prefixed
		// SHA-256.
		h := sha256.New()
		h.Write([]byte{transparency.LeafPrefix})
		h.Write(body)
		copy(leaves[i][:], h.Sum(nil))
	}
	return leaves
}

func TestVerifyInclusionProofRoundTripVariousSizes(t *testing.T) {
	for _, size := range []int{1, 2, 3, 5, 7, 8, 16, 17, 100, 257} {
		leaves := makeLeaves(size)
		root, proofs := buildTree(t, leaves)
		for i, p := range proofs {
			if err := transparency.VerifyInclusionProof(p, root); err != nil {
				t.Errorf("size=%d leaf=%d: VerifyInclusionProof: %v", size, i, err)
			}
		}
	}
}

func TestVerifyInclusionProofRejectsTampered(t *testing.T) {
	leaves := makeLeaves(8)
	root, proofs := buildTree(t, leaves)
	p := proofs[3]
	// Tamper with the leaf hash.
	tampered := p
	bad := make([]byte, 32)
	bad[0] = 0xff
	tampered.LeafHash = base64.StdEncoding.EncodeToString(bad)
	if err := transparency.VerifyInclusionProof(tampered, root); err == nil {
		t.Error("VerifyInclusionProof accepted tampered leaf_hash")
	}
	// Tamper with leaf_index.
	tampered = p
	tampered.LeafIndex = 0
	if err := transparency.VerifyInclusionProof(tampered, root); err == nil {
		t.Error("VerifyInclusionProof accepted tampered leaf_index")
	}
}

func TestVerifyConsistencyProofRoundTrip(t *testing.T) {
	cases := []struct {
		from, to int
	}{
		{1, 2},
		{2, 5},
		{3, 7},
		{4, 8},
		{5, 9},
		{8, 16},
		{50, 100},
	}
	leavesAll := makeLeaves(200)
	for _, tc := range cases {
		from := leavesAll[:tc.from]
		to := leavesAll[:tc.to]
		fromRoot := computeRoot(from)
		toRoot := computeRoot(to)
		path := computeConsistencyPath(leavesAll, int64(tc.from), int64(tc.to))
		p := transparency.ConsistencyProof{
			FromSize: int64(tc.from),
			ToSize:   int64(tc.to),
			Path:     hashesToBase64(path),
		}
		if err := transparency.VerifyConsistencyProof(p, fromRoot, toRoot); err != nil {
			t.Errorf("from=%d to=%d: %v", tc.from, tc.to, err)
		}
	}
}

func TestVerifyConsistencyProofRejectsTampered(t *testing.T) {
	leavesAll := makeLeaves(20)
	from := leavesAll[:5]
	to := leavesAll[:13]
	fromRoot := computeRoot(from)
	toRoot := computeRoot(to)
	path := computeConsistencyPath(leavesAll, 5, 13)
	p := transparency.ConsistencyProof{
		FromSize: 5,
		ToSize:   13,
		Path:     hashesToBase64(path),
	}
	// Tamper with the second root: verifier MUST reject.
	bad := [32]byte{}
	bad[0] = 0xff
	if err := transparency.VerifyConsistencyProof(p, fromRoot, bad); err == nil {
		t.Error("VerifyConsistencyProof accepted tampered second root")
	}
	// Tamper with from_size: verifier MUST reject.
	tampered := p
	tampered.FromSize = 6
	if err := transparency.VerifyConsistencyProof(tampered, fromRoot, toRoot); err == nil {
		t.Error("VerifyConsistencyProof accepted tampered from_size")
	}
}

func TestVerifyConsistencyProofEqualSizes(t *testing.T) {
	leaves := makeLeaves(7)
	root := computeRoot(leaves)
	p := transparency.ConsistencyProof{
		FromSize: 7,
		ToSize:   7,
		Path:     nil,
	}
	if err := transparency.VerifyConsistencyProof(p, root, root); err != nil {
		t.Errorf("equal sizes equal roots: %v", err)
	}
	// Equal sizes, different roots: reject.
	bad := [32]byte{}
	bad[0] = 0xff
	if err := transparency.VerifyConsistencyProof(p, root, bad); err == nil {
		t.Error("equal sizes different roots: want error")
	}
}

func TestSTHRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	leaves := makeLeaves(32)
	root := computeRoot(leaves)
	s := &transparency.SignedTreeHead{
		LogSize:   int64(len(leaves)),
		RootHash:  transparency.EncodeHash(root),
		Timestamp: time.Now().UTC(),
	}
	if err := transparency.SignSTH(signer, priv, "domain-fp", s); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	if err := transparency.VerifySTH(signer, pub, s); err != nil {
		t.Errorf("VerifySTH: %v", err)
	}
	if err := transparency.CheckSTHFresh(s, time.Now().UTC()); err != nil {
		t.Errorf("CheckSTHFresh fresh: %v", err)
	}
	// Tamper with log_size: signature breaks.
	s.LogSize = 999
	if err := transparency.VerifySTH(signer, pub, s); err == nil {
		t.Error("VerifySTH accepted tampered log_size")
	}
}

func TestCheckSTHFreshRejectsStale(t *testing.T) {
	s := &transparency.SignedTreeHead{
		LogSize:   1,
		RootHash:  transparency.EncodeHash(makeLeaves(1)[0]),
		Timestamp: time.Now().UTC().Add(-3 * time.Hour),
	}
	if err := transparency.CheckSTHFresh(s, time.Now().UTC()); err == nil {
		t.Error("CheckSTHFresh accepted a 3-hour-old STH; want error")
	}
}

func TestLogEntryValidate(t *testing.T) {
	now := time.Now().UTC()
	good := &transparency.LogEntry{
		Event:        transparency.EventPublish,
		UserID:       "alice@example.com",
		KeyID:        "fp",
		KeyType:      transparency.KeyTypeIdentity,
		Algorithm:    "ed25519",
		PublicKey:    "AAA=",
		Created:      now,
		LogTimestamp: now,
	}
	if err := good.Validate(); err != nil {
		t.Errorf("good: %v", err)
	}
	// rotate without supersedes
	bad := *good
	bad.Event = transparency.EventRotate
	if err := bad.Validate(); err == nil {
		t.Error("rotate without supersedes accepted")
	}
	// publish with supersedes
	bad = *good
	v := "old-fp"
	bad.Supersedes = &v
	if err := bad.Validate(); err == nil {
		t.Error("publish with supersedes accepted")
	}
	// revoke without revoked_at
	bad = *good
	bad.Event = transparency.EventRevoke
	if err := bad.Validate(); err == nil {
		t.Error("revoke without revoked_at accepted")
	}
	// revoke with required fields
	revAt := now
	rsn := "key_compromise"
	bad = *good
	bad.Event = transparency.EventRevoke
	bad.RevokedAt = &revAt
	bad.RevokedReason = &rsn
	if err := bad.Validate(); err != nil {
		t.Errorf("good revoke: %v", err)
	}
}

func TestHashLeafFromEntryDeterministic(t *testing.T) {
	now := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	e := transparency.LogEntry{
		Event:        transparency.EventPublish,
		UserID:       "alice@example.com",
		KeyID:        "fp",
		KeyType:      transparency.KeyTypeIdentity,
		Algorithm:    "ed25519",
		PublicKey:    "AAA=",
		Created:      now,
		LogTimestamp: now,
	}
	a, err := transparency.HashLeafFromEntry(e)
	if err != nil {
		t.Fatalf("HashLeafFromEntry a: %v", err)
	}
	b, err := transparency.HashLeafFromEntry(e)
	if err != nil {
		t.Fatalf("HashLeafFromEntry b: %v", err)
	}
	if a != b {
		t.Error("HashLeafFromEntry not deterministic")
	}
}
