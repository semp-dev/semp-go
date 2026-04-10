package crypto

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

// SessionContext is the constant info string used as the HKDF info argument
// when extracting the initial session PRK. Subsequent Expand calls use the
// per-key labels above.
const SessionContext = "SEMP-v1-session"

// KDF is the key derivation function abstraction. Both currently defined
// SEMP suites use HKDF-SHA-512.
type KDF interface {
	// Extract performs HKDF-Extract(salt, ikm) and returns the PRK.
	Extract(salt, ikm []byte) []byte

	// Expand performs HKDF-Expand(prk, info, length) and returns length
	// bytes of derived keying material.
	Expand(prk, info []byte, length int) []byte
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
// of session teardown.
//
// TODO(SESSION.md §2.4): use the platform secure-zero primitive once
// available; the skeleton uses a plain loop.
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
// Reference: SESSION.md §2.1, VECTORS.md §2.1.
//
// TODO(SESSION.md §2.1): implement once kdf is wired up.
func DeriveSessionKeys(kdf KDF, sharedSecret, clientNonce, serverNonce []byte) (*SessionKeys, error) {
	_, _, _, _ = kdf, sharedSecret, clientNonce, serverNonce
	return nil, nil
}

// DeriveRekeyKeys derives a fresh SessionKeys for a rekey exchange. It
// differs from DeriveSessionKeys only in the info context used (InfoRekey
// instead of SessionContext) and in the salt construction (rekey_nonce ||
// responder_nonce).
//
// Reference: SESSION.md §3.3.
//
// TODO(SESSION.md §3.3): implement.
func DeriveRekeyKeys(kdf KDF, sharedSecret, rekeyNonce, responderNonce []byte) (*SessionKeys, error) {
	_, _, _, _ = kdf, sharedSecret, rekeyNonce, responderNonce
	return nil, nil
}
