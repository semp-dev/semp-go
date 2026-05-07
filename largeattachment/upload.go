package largeattachment

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"semp.dev/semp-go/crypto"
)

// EncryptInput bundles the inputs to Encrypt. KEnclosure and
// Plaintext are required; the rest of the metadata fields populate
// the resulting Item. Suite supplies the AEAD per ATTACHMENTS.md
// §3.2: baseline suite uses chacha20-poly1305 (12-byte nonce); PQ
// suite uses xchacha20-poly1305 (24-byte nonce).
//
// URL MUST be the HTTPS URL the ciphertext will be retrievable at;
// it is bound into the AEAD additional data so an attacker cannot
// swap a victim's URL for their own. Operators that obtain the URL
// only after upload supply a pre-assigned URL from their storage
// provider before calling Encrypt; per §5 this is the standard
// flow when interleaving steps 9-10 with earlier steps.
//
// ID and AEADNonce are optional; when zero / nil the function
// generates a fresh ULID-shaped id and a fresh nonce. Tests pass
// non-nil values for deterministic output.
type EncryptInput struct {
	Suite      crypto.Suite
	KEnclosure []byte
	Plaintext  []byte
	Filename   string
	MimeType   string
	URL        string

	ID         string
	AEADNonce  []byte
	Extensions map[string]any
}

// EncryptResult is what Encrypt returns. Item is fully populated
// per §2.3 and ready to drop into the enclosure's
// `semp.dev/large-attachment` extension entry. Ciphertext is the
// AEAD output bytes the caller uploads to Item.URL.
type EncryptResult struct {
	Item       Item
	Ciphertext []byte
}

// Encrypt implements the §5 sender-side flow:
//
//  1. Generate attachment_id (ULID-shaped) if not supplied.
//  2. Derive K_attachment from K_enclosure per §3.1 HKDF-Expand.
//  3. Generate a fresh AEAD nonce per the suite's algorithm if
//     not supplied.
//  4. Construct the partly-populated item (id, filename, mime_type,
//     plaintext_size, url, aead_algorithm, aead_nonce; ciphertext_hash
//     and extensions left empty for AAD computation).
//  5. Compute AEAD additional-data per §3.2 (canonical JSON of the
//     item with ciphertext_hash, aead_nonce, extensions zeroed).
//  6. AEAD-encrypt the plaintext under K_attachment.
//  7. Compute ciphertext_hash over the ciphertext bytes.
//  8. Populate ciphertext_hash + extensions on the returned item.
//
// Encrypt does not upload anything; the caller uploads
// EncryptResult.Ciphertext to EncryptResult.Item.URL after Encrypt
// returns.
func Encrypt(in EncryptInput) (EncryptResult, error) {
	if in.Suite == nil {
		return EncryptResult{}, errors.New("largeattachment: nil suite")
	}
	if len(in.KEnclosure) == 0 {
		return EncryptResult{}, errors.New("largeattachment: empty K_enclosure")
	}
	if in.Plaintext == nil {
		return EncryptResult{}, errors.New("largeattachment: nil plaintext")
	}
	if in.Filename == "" || in.MimeType == "" || in.URL == "" {
		return EncryptResult{}, errors.New("largeattachment: filename, mime_type, and url are required")
	}
	if err := ValidateURL(in.URL); err != nil {
		return EncryptResult{}, err
	}

	algo, aead, err := aeadForSuite(in.Suite)
	if err != nil {
		return EncryptResult{}, err
	}

	id := in.ID
	if id == "" {
		id, err = newULID()
		if err != nil {
			return EncryptResult{}, fmt.Errorf("largeattachment: generate id: %w", err)
		}
	}

	nonce := in.AEADNonce
	if nonce == nil {
		nonce = make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return EncryptResult{}, fmt.Errorf("largeattachment: nonce random: %w", err)
		}
	}
	if len(nonce) != aead.NonceSize() {
		return EncryptResult{}, fmt.Errorf("largeattachment: nonce length %d, want %d for %s",
			len(nonce), aead.NonceSize(), algo)
	}

	kAttachment, err := DeriveAttachmentKey(in.Suite.KDF(), in.KEnclosure, id, aead.KeySize())
	if err != nil {
		return EncryptResult{}, err
	}

	// Build the partly-populated item for AAD. ciphertext_hash and
	// extensions are deliberately left empty here; AdditionalData
	// zeroes them out internally per §3.2 but we keep the pre-AAD
	// value clean for clarity.
	item := Item{
		ID:            id,
		Filename:      in.Filename,
		MimeType:      in.MimeType,
		PlaintextSize: int64(len(in.Plaintext)),
		URL:           in.URL,
		AEADAlgorithm: algo,
		AEADNonce:     base64.StdEncoding.EncodeToString(nonce),
	}
	aad, err := AdditionalData(item)
	if err != nil {
		return EncryptResult{}, fmt.Errorf("largeattachment: aad: %w", err)
	}
	ciphertext, err := aead.Seal(kAttachment, nonce, in.Plaintext, aad)
	if err != nil {
		return EncryptResult{}, fmt.Errorf("largeattachment: aead seal: %w", err)
	}
	item.CiphertextHash = CiphertextHash(ciphertext)
	if in.Extensions != nil {
		item.Extensions = in.Extensions
	}

	return EncryptResult{Item: item, Ciphertext: ciphertext}, nil
}

// Decrypt implements the §6 recipient-side flow:
//
//   - Derive K_attachment from K_enclosure per §3.1.
//   - Verify ciphertext_hash against the supplied ciphertext bytes.
//   - Reconstruct AEAD additional-data per §3.2.
//   - AEAD-open the ciphertext.
//
// Returns the plaintext bytes. Returns ErrCiphertextHashMismatch on
// hash mismatch (§7.2 ciphertext-integrity failure) before
// attempting AEAD open. Returns the AEAD-open error on
// authentication failure (§7.3 decryption-integrity failure).
func Decrypt(suite crypto.Suite, kEnclosure []byte, item Item, ciphertext []byte) ([]byte, error) {
	if suite == nil {
		return nil, errors.New("largeattachment: nil suite")
	}
	if len(kEnclosure) == 0 {
		return nil, errors.New("largeattachment: empty K_enclosure")
	}
	if err := item.Validate(); err != nil {
		return nil, err
	}
	algo, aead, err := aeadForSuite(suite)
	if err != nil {
		return nil, err
	}
	if item.AEADAlgorithm != algo {
		return nil, fmt.Errorf("largeattachment: item aead_algorithm %q does not match suite %q (expected %s)",
			item.AEADAlgorithm, suite.ID(), algo)
	}
	if err := VerifyCiphertextHash(item, ciphertext); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCiphertextHashMismatch, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(item.AEADNonce)
	if err != nil {
		return nil, fmt.Errorf("largeattachment: aead_nonce base64: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("largeattachment: aead_nonce length %d, want %d for %s",
			len(nonce), aead.NonceSize(), algo)
	}
	kAttachment, err := DeriveAttachmentKey(suite.KDF(), kEnclosure, item.ID, aead.KeySize())
	if err != nil {
		return nil, err
	}
	aad, err := AdditionalData(item)
	if err != nil {
		return nil, fmt.Errorf("largeattachment: aad: %w", err)
	}
	plaintext, err := aead.Open(kAttachment, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("largeattachment: aead open: %w", err)
	}
	return plaintext, nil
}

// ErrCiphertextHashMismatch is returned by Decrypt when the §6 step
// 3c hash check fails. Wraps the underlying VerifyCiphertextHash
// error so callers can use errors.Is to surface a §7.2 ciphertext-
// integrity failure to the user.
var ErrCiphertextHashMismatch = errors.New("largeattachment: ciphertext hash mismatch")

// aeadForSuite returns the (algorithm name, AEAD primitive,
// nonce size) tuple specified for the supplied suite per
// ATTACHMENTS.md §3.2. The baseline suite uses chacha20-poly1305
// with a 12-byte nonce; the PQ suite uses xchacha20-poly1305 with
// a 24-byte nonce.
//
// Returns an error for unrecognized suites so a future suite must
// be wired up explicitly rather than silently falling through.
func aeadForSuite(suite crypto.Suite) (string, crypto.AEAD, error) {
	switch suite.ID() {
	case crypto.SuiteIDX25519ChaCha20Poly1305:
		return AEADChaCha20Poly1305, suite.AEAD(), nil
	case crypto.SuiteIDPQKyber768X25519:
		// The PQ suite's envelope AEAD is chacha20-poly1305, but
		// §3.2 specifies xchacha20-poly1305 for attachments under
		// the PQ suite. Wrap the x/crypto package directly here so
		// the helper does not require a parallel public AEAD type
		// in semp.dev/semp-go/crypto.
		return AEADXChaCha20Poly1305, xchacha20poly1305AEAD{}, nil
	default:
		return "", nil, fmt.Errorf("largeattachment: no attachment AEAD wired for suite %q", suite.ID())
	}
}

// xchacha20poly1305AEAD is a thin adapter that satisfies crypto.AEAD
// using XChaCha20-Poly1305 with a 24-byte nonce. Used for the PQ
// suite's attachment AEAD per §3.2; the envelope still uses regular
// ChaCha20-Poly1305 with a 12-byte nonce, so this lives only in
// largeattachment rather than crypto.
type xchacha20poly1305AEAD struct{}

func (xchacha20poly1305AEAD) KeySize() int   { return chacha20poly1305.KeySize }
func (xchacha20poly1305AEAD) NonceSize() int { return chacha20poly1305.NonceSizeX }
func (xchacha20poly1305AEAD) Overhead() int  { return chacha20poly1305.Overhead }

func (xchacha20poly1305AEAD) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("largeattachment: invalid xchacha20-poly1305 key size")
	}
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != c.NonceSize() {
		return nil, errors.New("largeattachment: invalid xchacha20-poly1305 nonce size")
	}
	return c.Seal(nil, nonce, plaintext, ad), nil
}

func (xchacha20poly1305AEAD) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("largeattachment: invalid xchacha20-poly1305 key size")
	}
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != c.NonceSize() {
		return nil, errors.New("largeattachment: invalid xchacha20-poly1305 nonce size")
	}
	return c.Open(nil, nonce, ciphertext, ad)
}

// newULID returns a 26-character ULID-shaped string. The first 10
// characters encode 48 bits of milliseconds since the Unix epoch
// (Crockford base32); the last 16 encode 80 bits of randomness.
//
// Inlined here so the largeattachment package does not pull in an
// external ULID library or a dependency on the handshake package's
// internal helper.
func newULID() (string, error) {
	var bits [16]byte
	ms := uint64(time.Now().UnixMilli())
	bits[0] = byte(ms >> 40)
	bits[1] = byte(ms >> 32)
	bits[2] = byte(ms >> 24)
	bits[3] = byte(ms >> 16)
	bits[4] = byte(ms >> 8)
	bits[5] = byte(ms)
	if _, err := rand.Read(bits[6:]); err != nil {
		return "", err
	}
	// Crockford base32 alphabet (no I, L, O, U).
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var u uint64 = binary.BigEndian.Uint64(bits[:8])
	var u2 uint64 = binary.BigEndian.Uint64(bits[8:16])
	out := make([]byte, 26)
	for i := 25; i >= 13; i-- {
		out[i] = alphabet[u2&31]
		u2 >>= 5
	}
	for i := 12; i >= 0; i-- {
		out[i] = alphabet[u&31]
		u >>= 5
	}
	return string(out), nil
}

