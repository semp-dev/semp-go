package recovery_test

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand/v2"
	"testing"

	"semp.dev/semp-go/recovery"
)

// kBundleLen mirrors the §2.5 K_bundle width - the most important
// real-world Shamir input length for SEMP. Many tests use this so a
// regression on the 32-byte path is obvious.
const kBundleLen = 32

func randSecret(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestShamirRoundTrip exercises every (M, N) pair within spec
// bounds. Splitting is run once; combining is then run on every
// M-subset that contains the lowest-indexed shares (a representative
// sweep - exhaustively trying all M-of-N subsets is overkill). The
// secret length is the §2.5 K_bundle width.
func TestShamirRoundTrip(t *testing.T) {
	secret := randSecret(t, kBundleLen)
	for n := recovery.MinShamirThreshold; n <= recovery.MaxShamirTotalShares; n++ {
		for m := recovery.MinShamirThreshold; m <= n; m++ {
			shares, err := recovery.SplitSecret(secret, m, n, nil)
			if err != nil {
				t.Fatalf("Split(M=%d, N=%d): %v", m, n, err)
			}
			if len(shares) != n {
				t.Fatalf("Split(M=%d, N=%d) returned %d shares, want %d", m, n, len(shares), n)
			}
			got, err := recovery.CombineShares(shares[:m])
			if err != nil {
				t.Fatalf("Combine(M=%d of N=%d): %v", m, n, err)
			}
			if !bytes.Equal(got, secret) {
				t.Errorf("Combine(M=%d of N=%d) returned wrong secret", m, n)
			}
		}
	}
}

// TestShamirAnyMSubsetReconstructs confirms that any M-share subset
// (not just the first M) reconstructs the original. This is the
// substantive correctness property: §5.4 says ANY M shares suffice.
func TestShamirAnyMSubsetReconstructs(t *testing.T) {
	const m, n = 3, 5
	secret := randSecret(t, kBundleLen)
	shares, err := recovery.SplitSecret(secret, m, n, nil)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	// Try several different M-subsets.
	subsets := [][]int{
		{0, 1, 2},
		{0, 2, 4},
		{1, 3, 4},
		{2, 3, 4},
		{0, 1, 4},
	}
	for _, idx := range subsets {
		picked := make([]recovery.Share, len(idx))
		for k, i := range idx {
			picked[k] = shares[i]
		}
		got, err := recovery.CombineShares(picked)
		if err != nil {
			t.Errorf("Combine(subset %v): %v", idx, err)
			continue
		}
		if !bytes.Equal(got, secret) {
			t.Errorf("Combine(subset %v) returned wrong secret", idx)
		}
	}
}

// TestShamirInsufficientSharesDiverge confirms that fewer than M
// shares do NOT reconstruct the original. The math says the
// recovered byte for a missing share is statistically independent of
// the secret byte (over uniformly random polynomial coefficients).
//
// We probabilistically verify that with M-1 shares the reconstruction
// is something other than the secret. The collision probability is
// 1/256 per byte, ~1e-77 over 32 bytes, so a single trial is fine.
func TestShamirInsufficientSharesDiverge(t *testing.T) {
	const m, n = 3, 5
	secret := randSecret(t, kBundleLen)
	shares, err := recovery.SplitSecret(secret, m, n, nil)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	got, err := recovery.CombineShares(shares[:m-1])
	if err != nil {
		t.Fatalf("Combine(M-1): %v", err)
	}
	if bytes.Equal(got, secret) {
		t.Error("Combine(M-1 of N) recovered the secret; that violates the threshold")
	}
}

// TestShamirShareIndicesAreOneBased confirms every emitted share has
// a 1-based index in [1, N], and indices are unique. Index 0 is the
// secret itself and MUST not appear; the spec uses 1-based share
// indexes throughout.
func TestShamirShareIndicesAreOneBased(t *testing.T) {
	shares, err := recovery.SplitSecret(randSecret(t, 16), 2, 7, nil)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	seen := make(map[byte]struct{}, len(shares))
	for i, s := range shares {
		if s.Index == 0 {
			t.Errorf("share[%d] has index 0", i)
		}
		if int(s.Index) > 7 {
			t.Errorf("share[%d] has out-of-range index %d", i, s.Index)
		}
		if _, dup := seen[s.Index]; dup {
			t.Errorf("share[%d] index %d duplicates a prior share", i, s.Index)
		}
		seen[s.Index] = struct{}{}
	}
}

// TestSplitSecretDeterministicWithFixedRand confirms the split
// output is fully determined by (secret, M, N, randSrc). This is the
// property tests rely on for reproducibility.
func TestSplitSecretDeterministicWithFixedRand(t *testing.T) {
	secret := []byte("a sixteen-bytes!")
	rng1 := mrand.NewChaCha8([32]byte{1, 2, 3})
	rng2 := mrand.NewChaCha8([32]byte{1, 2, 3})
	a, err := recovery.SplitSecret(secret, 3, 5, rng1)
	if err != nil {
		t.Fatalf("Split #1: %v", err)
	}
	b, err := recovery.SplitSecret(secret, 3, 5, rng2)
	if err != nil {
		t.Fatalf("Split #2: %v", err)
	}
	for i := range a {
		if a[i].Index != b[i].Index {
			t.Errorf("share[%d] index drift: %d vs %d", i, a[i].Index, b[i].Index)
		}
		if !bytes.Equal(a[i].Value, b[i].Value) {
			t.Errorf("share[%d] value drift", i)
		}
	}
}

// TestSplitSecretDifferentSeedsDifferShares confirms two splits of
// the same secret with different RNG sources produce different
// share values. (Different shares MUST be possible; a static-output
// SSS would leak the secret.)
func TestSplitSecretDifferentSeedsDifferShares(t *testing.T) {
	secret := []byte("a sixteen-bytes!")
	rng1 := mrand.NewChaCha8([32]byte{1})
	rng2 := mrand.NewChaCha8([32]byte{2})
	a, err := recovery.SplitSecret(secret, 3, 5, rng1)
	if err != nil {
		t.Fatalf("Split #1: %v", err)
	}
	b, err := recovery.SplitSecret(secret, 3, 5, rng2)
	if err != nil {
		t.Fatalf("Split #2: %v", err)
	}
	allEqual := true
	for i := range a {
		if !bytes.Equal(a[i].Value, b[i].Value) {
			allEqual = false
			break
		}
	}
	if allEqual {
		t.Error("two splits with different RNG seeds produced identical shares")
	}
	// And both still reconstruct the original.
	if got, err := recovery.CombineShares(a[:3]); err != nil || !bytes.Equal(got, secret) {
		t.Errorf("Combine(a): got=%x err=%v", got, err)
	}
	if got, err := recovery.CombineShares(b[:3]); err != nil || !bytes.Equal(got, secret) {
		t.Errorf("Combine(b): got=%x err=%v", got, err)
	}
}

// TestSplitSecretParameterBounds walks every parameter rejection
// path: M < 2, N < M, N > 16, empty secret.
func TestSplitSecretParameterBounds(t *testing.T) {
	cases := []struct {
		name      string
		secret    []byte
		threshold int
		total     int
	}{
		{"empty secret", nil, 2, 3},
		{"threshold below minimum", []byte("hi"), 1, 3},
		{"threshold above total", []byte("hi"), 4, 3},
		{"total above max", []byte("hi"), 2, 17},
		{"zero threshold", []byte("hi"), 0, 3},
		{"zero total", []byte("hi"), 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := recovery.SplitSecret(tc.secret, tc.threshold, tc.total, nil); err == nil {
				t.Error("SplitSecret accepted out-of-bounds parameters")
			}
		})
	}
}

// TestCombineSharesRejectsBadInput walks every rejection path on the
// reconstruct side.
func TestCombineSharesRejectsBadInput(t *testing.T) {
	// Build a valid 3-of-5 split for source material.
	good, err := recovery.SplitSecret(randSecret(t, kBundleLen), 3, 5, nil)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	cases := []struct {
		name   string
		shares []recovery.Share
	}{
		{"empty", nil},
		{
			"empty share value",
			[]recovery.Share{{Index: 1, Value: nil}, {Index: 2, Value: nil}, {Index: 3, Value: nil}},
		},
		{
			"zero index",
			[]recovery.Share{good[0], {Index: 0, Value: good[1].Value}, good[2]},
		},
		{
			"duplicate index",
			[]recovery.Share{good[0], good[1], {Index: good[1].Index, Value: good[2].Value}},
		},
		{
			"mismatched length",
			[]recovery.Share{good[0], good[1], {Index: good[2].Index, Value: good[2].Value[:len(good[2].Value)-1]}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := recovery.CombineShares(tc.shares); err == nil {
				t.Error("CombineShares accepted invalid input")
			}
		})
	}
}

// TestShamirOneByteSecret exercises the smallest legal secret
// length, where every per-byte polynomial degenerates to a single
// evaluation over GF(256). Threshold M = 2 with 3 shares; combine
// any 2.
func TestShamirOneByteSecret(t *testing.T) {
	secret := []byte{0x42}
	shares, err := recovery.SplitSecret(secret, 2, 3, nil)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	for i := 0; i < 3; i++ {
		for j := i + 1; j < 3; j++ {
			got, err := recovery.CombineShares([]recovery.Share{shares[i], shares[j]})
			if err != nil {
				t.Errorf("Combine(%d,%d): %v", i, j, err)
				continue
			}
			if !bytes.Equal(got, secret) {
				t.Errorf("Combine(%d,%d) = %x, want %x", i, j, got, secret)
			}
		}
	}
}

// TestShamirMaxParameters exercises the spec's upper bound: M = N =
// 16. All 16 shares are needed (and sufficient) for reconstruction.
func TestShamirMaxParameters(t *testing.T) {
	secret := randSecret(t, kBundleLen)
	shares, err := recovery.SplitSecret(secret, 16, 16, nil)
	if err != nil {
		t.Fatalf("Split(M=N=16): %v", err)
	}
	if len(shares) != 16 {
		t.Fatalf("Split returned %d shares, want 16", len(shares))
	}
	got, err := recovery.CombineShares(shares)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("Combine(all 16) returned wrong secret")
	}
}

// TestShamirAcceptsMoreThanThreshold confirms the implementation is
// exact for any subset of size >= threshold, not just exactly
// threshold. Lagrange interpolation is over-determined-tolerant when
// the points are consistent.
func TestShamirAcceptsMoreThanThreshold(t *testing.T) {
	const m, n = 3, 7
	secret := randSecret(t, kBundleLen)
	shares, err := recovery.SplitSecret(secret, m, n, nil)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	for take := m; take <= n; take++ {
		got, err := recovery.CombineShares(shares[:take])
		if err != nil {
			t.Errorf("Combine(take=%d): %v", take, err)
			continue
		}
		if !bytes.Equal(got, secret) {
			t.Errorf("Combine(take=%d) returned wrong secret", take)
		}
	}
}

// TestShamirShuffledSharesReconstruct confirms input-order
// invariance: callers can assemble shares in any order and still
// reconstruct correctly (Lagrange is symmetric in the points).
func TestShamirShuffledSharesReconstruct(t *testing.T) {
	const m, n = 4, 7
	secret := randSecret(t, kBundleLen)
	shares, err := recovery.SplitSecret(secret, m, n, nil)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	rng := mrand.New(mrand.NewPCG(0xC0DE, 0xF00D))
	shuffled := make([]recovery.Share, len(shares))
	copy(shuffled, shares)
	rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	got, err := recovery.CombineShares(shuffled[:m])
	if err != nil {
		t.Fatalf("Combine(shuffled): %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("Combine(shuffled) returned wrong secret")
	}
}
