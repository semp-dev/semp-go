package crypto

import (
	"crypto/sha512"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF info labels used in SEMP session key derivation. Both currently
// defined suites use HKDF-SHA-512. The five labels below correspond to the
// five session keys derived from the ephemeral shared secret per
// SESSION.md §2.1.
//
// VECTORS.md §2.1 contains the canonical key derivation vectors that
// validate correct implementation of these labels.
const (
	InfoSessionEncC2S = "SEMP-v1-session-enc-c2s"
	InfoSessionEncS2C = "SEMP-v1-session-enc-s2c"
	InfoSessionMACC2S = "SEMP-v1-session-mac-c2s"
	InfoSessionMACS2C = "SEMP-v1-session-mac-s2c"
	InfoSessionEnvMAC = "SEMP-v1-session-env-mac"
)

// InfoRekey is the HKDF info context used when deriving keys for an
// in-session rekey exchange (SESSION.md §3.3). Distinct from the initial
// session info to prevent cross-context key confusion.
const InfoRekey = "SEMP-v1-rekey"

// SessionContext is the constant info string used by callers that want a
// generic session-context expansion. The five per-key labels above are the
// authoritative bound contexts; SessionContext is provided for clarity in
// documentation and is not used directly during DeriveSessionKeys.
const SessionContext = "SEMP-v1-session"

// sessionKeyLength is the length in bytes of every derived session key
// (SESSION.md §2.1).
const sessionKeyLength = 32

// KDF is the key derivation function abstraction. Both currently defined
// SEMP suites use HKDF-SHA-512.
type KDF interface {
	// Extract performs HKDF-Extract(salt, ikm) and returns the PRK.
	Extract(salt, ikm []byte) []byte

	// Expand performs HKDF-Expand(prk, info, length) and returns length
	// bytes of derived keying material.
	Expand(prk, info []byte, length int) []byte
}

// kdfHKDFSHA512 is the HKDF-SHA-512 KDF used by both currently defined
// SEMP suites (ENVELOPE.md §7.3.1).
type kdfHKDFSHA512 struct{}

// NewKDFHKDFSHA512 returns a KDF backed by HKDF-SHA-512. The returned value
// has no internal state and is safe for concurrent use.
func NewKDFHKDFSHA512() KDF { return kdfHKDFSHA512{} }

// Extract implements KDF.
func (kdfHKDFSHA512) Extract(salt, ikm []byte) []byte {
	return hkdf.Extract(sha512.New, ikm, salt)
}

// Expand implements KDF. HKDF-Expand only fails when the requested length
// exceeds 255*HashLen (16,320 bytes for SHA-512); the SEMP code base never
// requests anywhere close to that limit, so a panic on overflow is safe and
// surfaces the bug as fast as possible.
func (kdfHKDFSHA512) Expand(prk, info []byte, length int) []byte {
	r := hkdf.Expand(sha512.New, prk, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("crypto: HKDF-Expand failed (length too large?): " + err.Error())
	}
	return out
}

// SessionKeys holds the five symmetric keys derived from the handshake
// shared secret. Every field is exactly 32 bytes when populated. The struct
// MUST be erased via Erase before the Session that owns it is freed
// (SESSION.md §2.4).
type SessionKeys struct {
	// EncC2S encrypts client → server handshake messages.
	EncC2S []byte
	// EncS2C encrypts server → client handshake messages.
	EncS2C []byte
	// MACC2S authenticates client → server handshake messages.
	MACC2S []byte
	// MACS2C authenticates server → client handshake messages.
	MACS2C []byte
	// EnvMAC authenticates envelopes via seal.session_mac.
	EnvMAC []byte
}

// Erase zeroes every key field in place. Callers MUST invoke Erase as part
// of session teardown (SESSION.md §2.4).
func (k *SessionKeys) Erase() {
	if k == nil {
		return
	}
	for _, b := range [][]byte{k.EncC2S, k.EncS2C, k.MACC2S, k.MACS2C, k.EnvMAC} {
		Zeroize(b)
	}
}

// DeriveSessionKeys produces the five session keys from the ephemeral shared
// secret and the client/server nonces. The procedure is:
//
//  1. salt = client_nonce || server_nonce
//  2. PRK  = HKDF-Extract(salt, sharedSecret)
//  3. K_enc_c2s = HKDF-Expand(PRK, InfoSessionEncC2S, 32)
//  4. ... and so on for the four other labels.
//
// kdf may be nil; if so, NewKDFHKDFSHA512 is used. Both currently defined
// SEMP suites use HKDF-SHA-512.
//
// Reference: SESSION.md §2.1, VECTORS.md §2.1.
func DeriveSessionKeys(kdf KDF, sharedSecret, clientNonce, serverNonce []byte) (*SessionKeys, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("crypto: empty shared secret")
	}
	if len(clientNonce) == 0 || len(serverNonce) == 0 {
		return nil, errors.New("crypto: empty nonce")
	}
	if kdf == nil {
		kdf = NewKDFHKDFSHA512()
	}
	salt := make([]byte, 0, len(clientNonce)+len(serverNonce))
	salt = append(salt, clientNonce...)
	salt = append(salt, serverNonce...)
	prk := kdf.Extract(salt, sharedSecret)
	defer Zeroize(prk)

	return &SessionKeys{
		EncC2S: kdf.Expand(prk, []byte(InfoSessionEncC2S), sessionKeyLength),
		EncS2C: kdf.Expand(prk, []byte(InfoSessionEncS2C), sessionKeyLength),
		MACC2S: kdf.Expand(prk, []byte(InfoSessionMACC2S), sessionKeyLength),
		MACS2C: kdf.Expand(prk, []byte(InfoSessionMACS2C), sessionKeyLength),
		EnvMAC: kdf.Expand(prk, []byte(InfoSessionEnvMAC), sessionKeyLength),
	}, nil
}

// DeriveRekeyKeys derives a fresh SessionKeys for a rekey exchange. It
// differs from DeriveSessionKeys only in the salt construction (rekey_nonce
// || responder_nonce) and the per-key info contexts; the per-key labels are
// the same five SEMP-v1-session-* labels — the rekey context is implied by
// the use of fresh shared secret material derived from a fresh ephemeral
// agreement, not by a different label namespace. See SESSION.md §3.3 for
// the full procedure.
//
// Reference: SESSION.md §3.3.
func DeriveRekeyKeys(kdf KDF, sharedSecret, rekeyNonce, responderNonce []byte) (*SessionKeys, error) {
	// Per SESSION.md §3.3 the only differences from the initial derivation
	// are the salt and the (notional) info context. We model the context
	// switch by routing through DeriveSessionKeys with the new salt; the
	// per-key labels remain the same five constants.
	return DeriveSessionKeys(kdf, sharedSecret, rekeyNonce, responderNonce)
}
