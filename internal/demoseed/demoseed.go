// Package demoseed derives deterministic cryptographic key material from
// human-readable strings. It exists ONLY so the cmd/semp-server and
// cmd/semp-cli demo binaries can interoperate as a smoke test without any
// out-of-band key exchange.
//
// PRODUCTION CODE MUST NOT DERIVE KEYS FROM A STRING. EVER.
//
// Every helper in this package takes a `seed` and a label (identity or
// domain) and produces a deterministic keypair. Two binaries given the
// same `seed` and label produce byte-for-byte identical keypairs, which
// is the property the demo relies on. It is also the property that makes
// these helpers catastrophically insecure for any other use:
//
//   - Anyone who knows the seed can sign as any user.
//   - Anyone who knows the seed can decrypt any envelope.
//   - The seed has no forward secrecy and no compromise recovery.
//
// The package lives under internal/ so external code cannot accidentally
// import it.
package demoseed

import (
	"crypto/ed25519"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

// Identity returns the Ed25519 keypair derived from (seed, identity). The
// matching call to Identity on a different process with the same seed and
// identity yields the byte-for-byte identical keypair.
func Identity(seed, identity string) (ed25519.PublicKey, ed25519.PrivateKey) {
	sum := sha256.Sum256([]byte("identity:" + seed + ":" + identity))
	priv := ed25519.NewKeyFromSeed(sum[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// Encryption returns the X25519 keypair derived from (seed, identity).
// The "scalar" half is the SHA-256 of the labeled input; the public half
// is X25519(scalar, basepoint). curve25519.X25519 performs scalar clamping
// internally so an arbitrary 32-byte SHA-256 output is a valid X25519
// scalar.
func Encryption(seed, identity string) (pub, priv []byte, err error) {
	sum := sha256.Sum256([]byte("encryption:" + seed + ":" + identity))
	priv = sum[:]
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return pub, append([]byte(nil), priv...), nil
}

// DomainSigning returns the Ed25519 keypair derived from (seed, domain).
// Used by the demo server as its long-term domain signing key.
func DomainSigning(seed, domain string) (ed25519.PublicKey, ed25519.PrivateKey) {
	sum := sha256.Sum256([]byte("domain-signing:" + seed + ":" + domain))
	priv := ed25519.NewKeyFromSeed(sum[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// DomainEncryption returns the X25519 keypair derived from (seed, domain).
// Used by the demo server to unwrap K_brief from envelopes addressed to
// users on its domain.
func DomainEncryption(seed, domain string) (pub, priv []byte, err error) {
	sum := sha256.Sum256([]byte("domain-encryption:" + seed + ":" + domain))
	priv = sum[:]
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return pub, append([]byte(nil), priv...), nil
}
