package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
)

// Kyber768 size constants from cloudflare/circl. Re-exported here with
// the SEMP naming convention so downstream callers don't need to know
// about the underlying library's package layout.
const (
	// Kyber768PublicKeySize is the wire size of a Kyber768 public key.
	Kyber768PublicKeySize = kyber768.PublicKeySize // 1184

	// Kyber768PrivateKeySize is the wire size of a Kyber768 private key.
	Kyber768PrivateKeySize = kyber768.PrivateKeySize // 2400

	// Kyber768CiphertextSize is the wire size of a Kyber768 encapsulated
	// ciphertext.
	Kyber768CiphertextSize = kyber768.CiphertextSize // 1088

	// Kyber768SharedKeySize is the wire size of a Kyber768 shared key.
	// Matches X25519SharedKeySize and the SEMP HKDF input width.
	Kyber768SharedKeySize = kyber768.SharedKeySize // 32
)

// HybridPublicKeySize is the wire size of a concatenated X25519 || Kyber768
// public key — what HybridKEMKyber768X25519.GenerateKeyPair returns as
// the first element and what the client sends as its ephemeral pub key
// during the handshake.
const HybridPublicKeySize = curve25519.PointSize + Kyber768PublicKeySize // 1216

// HybridPrivateKeySize is the wire size of a concatenated X25519 || Kyber768
// private key — held only in memory by the initiator between its init
// message and its receipt of the server's response.
const HybridPrivateKeySize = curve25519.ScalarSize + Kyber768PrivateKeySize // 2432

// HybridCiphertextSize is the wire size of the concatenated
// X25519 ephemeral public key || Kyber768 ciphertext the responder sends
// back in its response message. The responder does NOT need a Kyber
// keypair of its own; it encapsulates directly under the initiator's
// Kyber pub.
const HybridCiphertextSize = curve25519.PointSize + Kyber768CiphertextSize // 1120

// HybridSharedSecretSize is the length of the combined IKM that the
// hybrid KEM feeds into HKDF. It is exactly Kyber768SharedKeySize +
// X25519 (32) = 64 bytes. SESSION.md §4.1 defines the concatenation
// order as Kyber first, X25519 second; this constant reflects that.
const HybridSharedSecretSize = Kyber768SharedKeySize + curve25519.PointSize // 64

// kemHybridKyber768X25519 implements the SEMP post-quantum hybrid KEM
// defined in SESSION.md §4.1.
//
// Wire model (asymmetric, KEM-style):
//
//   - Initiator generates (x25519Pair, kyberPair) and sends
//     x25519Pub || kyberPub as its ephemeral public key (1216 bytes).
//
//   - Responder receives that blob, generates its own X25519 ephemeral
//     keypair, performs X25519 scalar multiplication against the
//     initiator's X25519 pub, encapsulates a Kyber shared key under the
//     initiator's Kyber pub, concatenates the two shared secrets as
//     (K_kyber || K_x25519), and returns the combined ciphertext as
//     responderX25519Pub || kyberCiphertext (1120 bytes). This
//     ciphertext is what goes on the wire as the "server ephemeral key"
//     field in the ServerResponse message — the same slot the baseline
//     X25519 suite uses for a plain 32-byte public key.
//
//   - Initiator receives the responder's wire blob, splits it into
//     responderX25519Pub and kyberCiphertext, performs X25519 against
//     its own X25519 private, decapsulates the Kyber ciphertext with
//     its Kyber private, concatenates the two shared secrets in the
//     same order, and arrives at the identical combined shared secret.
//
// The resulting 64-byte shared secret feeds directly into HKDF-Extract
// per SESSION.md §4.1 ("IKM = K_kyber || K_x25519").
//
// The crypto.KEM interface is satisfied by this type: GenerateKeyPair
// is the initiator-side keygen, Encapsulate is the responder-side
// "compute-shared-and-pack-ciphertext" call, and Decapsulate is the
// initiator-side "unpack-and-combine" call. Agree is NOT supported
// because hybrid Kyber has no Diffie-Hellman-style agree primitive —
// callers that expect symmetric DH (e.g. legacy X25519 code) must use
// Encapsulate/Decapsulate instead. Agree returns a descriptive error.
type kemHybridKyber768X25519 struct{}

// NewKEMHybridKyber768X25519 returns the SEMP post-quantum hybrid KEM.
// The returned value has no internal state and is safe for concurrent
// use.
func NewKEMHybridKyber768X25519() KEM { return kemHybridKyber768X25519{} }

// GenerateKeyPair returns a fresh (x25519Pub || kyberPub, x25519Priv ||
// kyberPriv) keypair. The initiator calls this once during handshake
// setup and sends the public half as its ephemeral key.
func (kemHybridKyber768X25519) GenerateKeyPair() (publicKey, privateKey []byte, err error) {
	xPub, xPriv, err := NewKEMX25519().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hybrid x25519 keygen: %w", err)
	}
	kyberPub, kyberPriv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		Zeroize(xPriv)
		return nil, nil, fmt.Errorf("crypto: hybrid kyber768 keygen: %w", err)
	}

	pub := make([]byte, 0, HybridPublicKeySize)
	pub = append(pub, xPub...)
	kyberPubBytes := make([]byte, Kyber768PublicKeySize)
	kyberPub.Pack(kyberPubBytes)
	pub = append(pub, kyberPubBytes...)

	priv := make([]byte, 0, HybridPrivateKeySize)
	priv = append(priv, xPriv...)
	Zeroize(xPriv) // we've copied it; erase the original
	kyberPrivBytes := make([]byte, Kyber768PrivateKeySize)
	kyberPriv.Pack(kyberPrivBytes)
	priv = append(priv, kyberPrivBytes...)

	return pub, priv, nil
}

// Encapsulate is the responder-side half of the handshake. It takes
// the initiator's hybrid public key (x25519Pub || kyberPub), generates
// its own ephemeral X25519 keypair, performs X25519 DH against the
// initiator's X25519 pub, encapsulates a Kyber shared key under the
// initiator's Kyber pub, and returns:
//
//   - sharedSecret: K_kyber || K_x25519 (64 bytes) per SESSION.md §4.1
//   - ciphertext: responderX25519Pub || kyberCiphertext (1120 bytes)
//
// The responder does not need to retain any state after this call —
// its ephemeral X25519 private key is zeroized internally before
// return.
func (kemHybridKyber768X25519) Encapsulate(remotePub []byte) (sharedSecret, ciphertext []byte, err error) {
	if len(remotePub) != HybridPublicKeySize {
		return nil, nil, fmt.Errorf("crypto: hybrid Encapsulate: remote public key length %d, want %d",
			len(remotePub), HybridPublicKeySize)
	}
	xRemote := remotePub[:curve25519.PointSize]
	kyberRemoteBytes := remotePub[curve25519.PointSize:]

	// Unpack the Kyber public key. Kyber768's Unpack panics on wrong
	// size; we've already guaranteed the slice length above so this is
	// safe, but guard against internal package regressions.
	var kyberPub kyber768.PublicKey
	if len(kyberRemoteBytes) != Kyber768PublicKeySize {
		return nil, nil, fmt.Errorf("crypto: hybrid Encapsulate: kyber pub size %d, want %d",
			len(kyberRemoteBytes), Kyber768PublicKeySize)
	}
	kyberPub.Unpack(kyberRemoteBytes)

	// X25519 half: fresh ephemeral pair, scalar mult against the
	// initiator's X25519 pub.
	xEphPub, xEphPriv, err := NewKEMX25519().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hybrid Encapsulate: x25519 keygen: %w", err)
	}
	defer Zeroize(xEphPriv)
	xSS, err := NewKEMX25519().Agree(xEphPriv, xRemote)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hybrid Encapsulate: x25519 agree: %w", err)
	}
	defer Zeroize(xSS)

	// Kyber half: encapsulate under the initiator's Kyber pub. circl's
	// EncapsulateTo writes the ciphertext and shared key into
	// caller-provided buffers.
	kyberCt := make([]byte, Kyber768CiphertextSize)
	kyberSS := make([]byte, Kyber768SharedKeySize)
	kyberPub.EncapsulateTo(kyberCt, kyberSS, nil)
	defer Zeroize(kyberSS)

	// Shared secret: K_kyber || K_x25519 per SESSION.md §4.1.
	shared := make([]byte, 0, HybridSharedSecretSize)
	shared = append(shared, kyberSS...)
	shared = append(shared, xSS...)

	// Ciphertext wire format: responderX25519Pub || kyberCiphertext.
	ct := make([]byte, 0, HybridCiphertextSize)
	ct = append(ct, xEphPub...)
	ct = append(ct, kyberCt...)

	return shared, ct, nil
}

// Decapsulate is the initiator-side half. It takes the responder's
// combined ciphertext (responderX25519Pub || kyberCiphertext) and the
// initiator's hybrid private key (x25519Priv || kyberPriv), performs
// X25519 against the responder's ephemeral pub, decapsulates the
// Kyber ciphertext with its Kyber private, and returns the combined
// shared secret.
func (kemHybridKyber768X25519) Decapsulate(ciphertext, localPriv []byte) (sharedSecret []byte, err error) {
	if len(ciphertext) != HybridCiphertextSize {
		return nil, fmt.Errorf("crypto: hybrid Decapsulate: ciphertext length %d, want %d",
			len(ciphertext), HybridCiphertextSize)
	}
	if len(localPriv) != HybridPrivateKeySize {
		return nil, fmt.Errorf("crypto: hybrid Decapsulate: private key length %d, want %d",
			len(localPriv), HybridPrivateKeySize)
	}
	xRemotePub := ciphertext[:curve25519.PointSize]
	kyberCt := ciphertext[curve25519.PointSize:]
	xLocalPriv := localPriv[:curve25519.ScalarSize]
	kyberPrivBytes := localPriv[curve25519.ScalarSize:]

	// X25519 half.
	xSS, err := NewKEMX25519().Agree(xLocalPriv, xRemotePub)
	if err != nil {
		return nil, fmt.Errorf("crypto: hybrid Decapsulate: x25519 agree: %w", err)
	}
	defer Zeroize(xSS)

	// Kyber half.
	var kyberPriv kyber768.PrivateKey
	kyberPriv.Unpack(kyberPrivBytes)
	kyberSS := make([]byte, Kyber768SharedKeySize)
	kyberPriv.DecapsulateTo(kyberSS, kyberCt)
	defer Zeroize(kyberSS)

	// Combined shared secret: K_kyber || K_x25519.
	shared := make([]byte, 0, HybridSharedSecretSize)
	shared = append(shared, kyberSS...)
	shared = append(shared, xSS...)
	return shared, nil
}

// Agree is not supported by the hybrid KEM. Kyber768 is a KEM, not a
// Diffie-Hellman primitive — the responder must use Encapsulate to
// derive the shared secret and produce a ciphertext for the initiator
// to Decapsulate. Calling Agree on a hybrid KEM returns a descriptive
// error so legacy X25519 code paths (which call Agree directly) get a
// clear failure rather than a silent protocol mismatch.
func (kemHybridKyber768X25519) Agree(localPrivate, remotePublic []byte) (sharedSecret []byte, err error) {
	return nil, errors.New("crypto: hybrid Kyber768+X25519 KEM does not support Agree; use Encapsulate/Decapsulate")
}
