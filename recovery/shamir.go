package recovery

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Shamir parameter bounds per RECOVERY.md §5.1.
//
// 2 <= threshold <= total_shares <= 16. The lower bound on threshold
// is the spec's normative floor (a 1-of-N split would expose the
// secret to any single device). The upper bound on total_shares is
// the spec's normative cap.
const (
	// MinShamirThreshold is the minimum reconstruction threshold M
	// per RECOVERY.md §5.1. A 1-of-N split is rejected.
	MinShamirThreshold = 2

	// MaxShamirTotalShares is the maximum share count N per
	// RECOVERY.md §5.1.
	MaxShamirTotalShares = 16
)

// Share is a single Shamir share over GF(256). The share index is the
// 1-based polynomial-evaluation x-coordinate; the value is one byte
// per secret byte (the polynomial is evaluated independently per
// secret byte). Index 0 is reserved for the secret itself and MUST
// never appear in a share.
type Share struct {
	Index byte
	Value []byte
}

// SplitSecret applies Shamir's Secret Sharing over GF(256) to secret
// with threshold M and total share count N per RECOVERY.md §5.1. It
// returns N shares; any M of them suffice to reconstruct via
// CombineShares.
//
// Per RECOVERY.md §5.1, callers MUST satisfy 2 <= threshold <=
// totalShares <= 16. The function rejects out-of-range parameters.
//
// randSrc supplies the polynomial coefficients above the constant
// term (the secret byte). The function consumes
// (threshold - 1) * len(secret) bytes from randSrc per call. If
// randSrc is nil, crypto/rand.Reader is used.
//
// SplitSecret does not retain or zeroize the secret; the caller is
// responsible for the secret's memory lifetime.
func SplitSecret(secret []byte, threshold, totalShares int, randSrc io.Reader) ([]Share, error) {
	if len(secret) == 0 {
		return nil, errors.New("recovery: split secret is empty")
	}
	if threshold < MinShamirThreshold {
		return nil, fmt.Errorf("recovery: threshold %d below minimum %d", threshold, MinShamirThreshold)
	}
	if totalShares < threshold {
		return nil, fmt.Errorf("recovery: total_shares %d below threshold %d", totalShares, threshold)
	}
	if totalShares > MaxShamirTotalShares {
		return nil, fmt.Errorf("recovery: total_shares %d above maximum %d", totalShares, MaxShamirTotalShares)
	}
	if randSrc == nil {
		randSrc = rand.Reader
	}

	shares := make([]Share, totalShares)
	for i := range shares {
		shares[i] = Share{Index: byte(i + 1), Value: make([]byte, len(secret))}
	}

	// One polynomial per secret byte. Coefficient 0 is the secret
	// byte; coefficients 1..threshold-1 are random.
	coeffs := make([]byte, threshold)
	for j, sb := range secret {
		coeffs[0] = sb
		if _, err := io.ReadFull(randSrc, coeffs[1:]); err != nil {
			return nil, fmt.Errorf("recovery: shamir random: %w", err)
		}
		for i := range shares {
			shares[i].Value[j] = polyEval(coeffs, shares[i].Index)
		}
	}
	return shares, nil
}

// CombineShares reconstructs the secret from at least threshold
// shares per RECOVERY.md §5.4. Each share's Value MUST have the same
// length; that common length is the recovered secret's length.
//
// Returns an error when:
//   - shares is empty
//   - any share value is empty or differs in length from the others
//   - any share index is zero (the polynomial constant term lives at
//     x = 0; a "share" at x = 0 would BE the secret)
//   - any two shares have the same index
//
// CombineShares does not check that the caller provided exactly
// threshold shares; supplying more than threshold is well-defined
// (Lagrange interpolation is exact for any subset >= threshold) and
// supplying fewer yields a nonsense byte string with no error. The
// caller MUST track the intended threshold against the manifest per
// §5.4.
func CombineShares(shares []Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("recovery: combine got no shares")
	}
	secretLen := len(shares[0].Value)
	if secretLen == 0 {
		return nil, errors.New("recovery: combine got empty share value")
	}
	xs := make([]byte, len(shares))
	seen := make(map[byte]struct{}, len(shares))
	for i, s := range shares {
		if s.Index == 0 {
			return nil, fmt.Errorf("recovery: share[%d] has invalid index 0", i)
		}
		if _, dup := seen[s.Index]; dup {
			return nil, fmt.Errorf("recovery: share index %d appears more than once", s.Index)
		}
		seen[s.Index] = struct{}{}
		if len(s.Value) != secretLen {
			return nil, fmt.Errorf("recovery: share[%d] value length %d differs from share[0] length %d",
				i, len(s.Value), secretLen)
		}
		xs[i] = s.Index
	}

	out := make([]byte, secretLen)
	ys := make([]byte, len(shares))
	for j := 0; j < secretLen; j++ {
		for i, s := range shares {
			ys[i] = s.Value[j]
		}
		out[j] = lagrangeInterpolateAtZero(xs, ys)
	}
	return out, nil
}

// polyEval evaluates the polynomial coeffs[0] + coeffs[1]*x + ... +
// coeffs[k]*x^k at point x in GF(256), using Horner's method.
func polyEval(coeffs []byte, x byte) byte {
	var y byte
	for k := len(coeffs) - 1; k >= 0; k-- {
		y = gf256Mul(y, x) ^ coeffs[k]
	}
	return y
}

// lagrangeInterpolateAtZero returns p(0) where p is the unique
// polynomial of degree len(xs) - 1 passing through every (xs[i],
// ys[i]) point, computed in GF(256).
//
// L_i(0) = product over k != i of x_k / (x_k - x_i). In GF(2^n)
// addition and subtraction are both XOR, so x_k - x_i collapses to
// x_k ^ x_i. With distinct, non-zero x values the denominators are
// all non-zero and the inversion is well-defined.
func lagrangeInterpolateAtZero(xs, ys []byte) byte {
	var result byte
	for i := range xs {
		num := byte(1)
		den := byte(1)
		for k := range xs {
			if k == i {
				continue
			}
			num = gf256Mul(num, xs[k])
			den = gf256Mul(den, xs[k]^xs[i])
		}
		basis := gf256Mul(num, gf256Inv(den))
		result ^= gf256Mul(ys[i], basis)
	}
	return result
}

// GF(256) tables under the AES reduction polynomial x^8 + x^4 + x^3 +
// x + 1 (0x11b) with generator g = 3. The multiplicative group has
// order 255 and is cyclic. gf256Exp[i] = g^i for i in [0, 254];
// gf256Exp[255] is wrapped to gf256Exp[0] = 1 so that gf256Inv can
// index 255 - log[1] = 255 directly without a modulo.
var (
	gf256Exp [256]byte
	gf256Log [256]byte
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		gf256Exp[i] = x
		gf256Log[x] = byte(i)
		x = gf256MulRaw(x, 3)
	}
	gf256Exp[255] = 1
	// gf256Log[0] is conventionally undefined; the multiplication and
	// inversion paths short-circuit on a zero argument before
	// indexing the log table.
}

// gf256MulRaw multiplies two GF(256) elements via shift/XOR with the
// AES reduction polynomial. Used only at init() to seed the log/exp
// tables; runtime callers use gf256Mul instead.
func gf256MulRaw(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			p ^= a
		}
		hiBit := a & 0x80
		a <<= 1
		if hiBit != 0 {
			a ^= 0x1b // poly 0x11b minus the implicit high bit
		}
		b >>= 1
	}
	return p
}

// gf256Mul multiplies two GF(256) elements via the log/exp tables.
// Returns 0 when either argument is 0 (log of 0 is undefined; the
// short-circuit avoids indexing gf256Log[0]).
func gf256Mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gf256Exp[(int(gf256Log[a])+int(gf256Log[b]))%255]
}

// gf256Inv returns the multiplicative inverse of a in GF(256).
//
// Per the spec's distinct-share-index requirement (RECOVERY.md §5.2
// / §5.4), this function is invoked in lagrangeInterpolateAtZero
// only on x_k ^ x_i for k != i with all x_* distinct, so the
// argument is always non-zero. gf256Inv panics on a zero argument
// rather than returning a wrong-but-not-erroring value.
func gf256Inv(a byte) byte {
	if a == 0 {
		panic("recovery: gf256Inv(0)")
	}
	return gf256Exp[255-int(gf256Log[a])]
}
