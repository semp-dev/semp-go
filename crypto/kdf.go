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
	// InfoSessionResumption labels the K_resumption HKDF expansion per
	// SESSION.md section 2.1. K_resumption is NOT used to encrypt or
	// MAC any message in the current session; it is the secret a
	// server retains so that, mixed with a fresh ephemeral DH on a
	// later resume attempt, the resumed session derives a new key
	// schedule. See HANDSHAKE.md section 2.8.3 and SESSION.md
	// section 2.7.
	InfoSessionResumption = "SEMP-v1-session-resumption"
)

// Rekey HKDF info labels.
//
// Per VECTORS.md §2.2 and SESSION.md §3.3, rekey derivation reuses the
// same per-key SEMP-v1-session-* labels as the initial handshake. The
// cross-context separation between an initial-handshake derivation and
// a rekey derivation comes from the salt change (rekey_nonce ||
// responder_nonce vs client_nonce || server_nonce), NOT from the
// expand labels. The "SEMP-v1-rekey" context name in SESSION.md §3.3
// is conceptual, not a literal HKDF info label.
//
// These aliases exist so that callers reading rekey-derivation code
// can reach for `InfoRekeyEncC2S` and get the same string the spec
// requires; the underlying value is intentionally identical to
// `InfoSessionEncC2S`.
const (
	InfoRekeyEncC2S = InfoSessionEncC2S
	InfoRekeyEncS2C = InfoSessionEncS2C
	InfoRekeyMACC2S = InfoSessionMACC2S
	InfoRekeyMACS2C = InfoSessionMACS2C
	InfoRekeyEnvMAC = InfoSessionEnvMAC
)

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

// SessionKeys holds the symmetric keys derived from the handshake
// shared secret. Every populated field is exactly 32 bytes. The struct
// MUST be erased via Erase before the Session that owns it is freed
// (SESSION.md §2.4).
//
// EncC2S, EncS2C, MACC2S, MACS2C, and EnvMAC are the five
// in-session keys. Resumption is the optional sixth key per
// SESSION.md section 2.1: a server that supports resumption retains
// it; clients leave it empty (or, for stateless ticket flows, the
// server stores it inside the ticket and never returns it
// directly).
type SessionKeys struct {
	// EncC2S encrypts client -> server handshake messages.
	EncC2S []byte
	// EncS2C encrypts server -> client handshake messages.
	EncS2C []byte
	// MACC2S authenticates client -> server handshake messages.
	MACC2S []byte
	// MACS2C authenticates server -> client handshake messages.
	MACS2C []byte
	// EnvMAC authenticates envelopes via seal.session_mac.
	EnvMAC []byte
	// Resumption is the K_resumption secret retained for a future
	// resume attempt per HANDSHAKE.md §2.8. Servers that issue
	// resumption tickets bind this value into the ticket and erase
	// the in-memory copy after issuance. Clients do not see this
	// value.
	Resumption []byte
}

// Erase zeroes every key field in place. Callers MUST invoke Erase as part
// of session teardown (SESSION.md §2.4).
func (k *SessionKeys) Erase() {
	if k == nil {
		return
	}
	for _, b := range [][]byte{k.EncC2S, k.EncS2C, k.MACC2S, k.MACS2C, k.EnvMAC, k.Resumption} {
		Zeroize(b)
	}
}

// DeriveSessionKeys produces the six session keys from the ephemeral
// shared secret and the client/server nonces. The procedure is:
//
//  1. salt = client_nonce || server_nonce
//  2. PRK  = HKDF-Extract(salt, sharedSecret)
//  3. K_enc_c2s     = HKDF-Expand(PRK, InfoSessionEncC2S, 32)
//  4. ... and so on for the four other in-session labels.
//  5. K_resumption  = HKDF-Expand(PRK, InfoSessionResumption, 32)
//
// kdf may be nil; if so, NewKDFHKDFSHA512 is used. Both currently
// defined SEMP suites use HKDF-SHA-512.
//
// Reference: SESSION.md §2.1, HANDSHAKE.md §2.8, VECTORS.md §2.1.
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
		EncC2S:     kdf.Expand(prk, []byte(InfoSessionEncC2S), sessionKeyLength),
		EncS2C:     kdf.Expand(prk, []byte(InfoSessionEncS2C), sessionKeyLength),
		MACC2S:     kdf.Expand(prk, []byte(InfoSessionMACC2S), sessionKeyLength),
		MACS2C:     kdf.Expand(prk, []byte(InfoSessionMACS2C), sessionKeyLength),
		EnvMAC:     kdf.Expand(prk, []byte(InfoSessionEnvMAC), sessionKeyLength),
		Resumption: kdf.Expand(prk, []byte(InfoSessionResumption), sessionKeyLength),
	}, nil
}

// DeriveResumedSessionKeys derives a fresh SessionKeys for a resumed
// session per HANDSHAKE.md §2.8.3. The HKDF-Extract input keying
// material is the concatenation of the fresh ephemeral DH output and
// the resumption secret recovered from the ticket; the salt is
// client_nonce || server_nonce, same as the full-handshake derivation.
// The five in-session keys and the next resumption secret use the
// same labels as DeriveSessionKeys, so the output schedule is
// indistinguishable from a full handshake at the per-key level: only
// the IKM mixing differs.
//
// Mixing both inputs preserves forward secrecy on resumption: an
// attacker who steals the ticket alone cannot derive the resumed
// session's keys without also breaking the ephemeral DH assumption.
func DeriveResumedSessionKeys(kdf KDF, ephemeralSharedSecret, resumptionSecret, clientNonce, serverNonce []byte) (*SessionKeys, error) {
	if len(ephemeralSharedSecret) == 0 {
		return nil, errors.New("crypto: empty ephemeral shared secret")
	}
	if len(resumptionSecret) == 0 {
		return nil, errors.New("crypto: empty resumption secret")
	}
	if len(clientNonce) == 0 || len(serverNonce) == 0 {
		return nil, errors.New("crypto: empty nonce")
	}
	if kdf == nil {
		kdf = NewKDFHKDFSHA512()
	}
	ikm := make([]byte, 0, len(ephemeralSharedSecret)+len(resumptionSecret))
	ikm = append(ikm, ephemeralSharedSecret...)
	ikm = append(ikm, resumptionSecret...)
	defer Zeroize(ikm)
	salt := make([]byte, 0, len(clientNonce)+len(serverNonce))
	salt = append(salt, clientNonce...)
	salt = append(salt, serverNonce...)
	prk := kdf.Extract(salt, ikm)
	defer Zeroize(prk)

	return &SessionKeys{
		EncC2S:     kdf.Expand(prk, []byte(InfoSessionEncC2S), sessionKeyLength),
		EncS2C:     kdf.Expand(prk, []byte(InfoSessionEncS2C), sessionKeyLength),
		MACC2S:     kdf.Expand(prk, []byte(InfoSessionMACC2S), sessionKeyLength),
		MACS2C:     kdf.Expand(prk, []byte(InfoSessionMACS2C), sessionKeyLength),
		EnvMAC:     kdf.Expand(prk, []byte(InfoSessionEnvMAC), sessionKeyLength),
		Resumption: kdf.Expand(prk, []byte(InfoSessionResumption), sessionKeyLength),
	}, nil
}

// DeriveRekeyKeys derives a fresh SessionKeys for a rekey exchange.
// Per SESSION.md §3.3 and VECTORS.md §2.2, the rekey derivation reuses
// the same per-key SEMP-v1-session-* expand labels as the initial
// handshake; the cross-context separation comes from the salt change
// (rekey_nonce || responder_nonce vs client_nonce || server_nonce),
// not from the expand labels. The InfoRekey* aliases used below
// resolve to the session labels by definition.
// The salt is rekey_nonce || responder_nonce.
//
// Reference: SESSION.md §3.3.
func DeriveRekeyKeys(kdf KDF, sharedSecret, rekeyNonce, responderNonce []byte) (*SessionKeys, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("crypto: empty shared secret")
	}
	if len(rekeyNonce) == 0 || len(responderNonce) == 0 {
		return nil, errors.New("crypto: empty nonce")
	}
	if kdf == nil {
		kdf = NewKDFHKDFSHA512()
	}
	salt := make([]byte, 0, len(rekeyNonce)+len(responderNonce))
	salt = append(salt, rekeyNonce...)
	salt = append(salt, responderNonce...)
	prk := kdf.Extract(salt, sharedSecret)
	defer Zeroize(prk)

	return &SessionKeys{
		EncC2S: kdf.Expand(prk, []byte(InfoRekeyEncC2S), sessionKeyLength),
		EncS2C: kdf.Expand(prk, []byte(InfoRekeyEncS2C), sessionKeyLength),
		MACC2S: kdf.Expand(prk, []byte(InfoRekeyMACC2S), sessionKeyLength),
		MACS2C: kdf.Expand(prk, []byte(InfoRekeyMACS2C), sessionKeyLength),
		EnvMAC: kdf.Expand(prk, []byte(InfoRekeyEnvMAC), sessionKeyLength),
	}, nil
}
