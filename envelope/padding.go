package envelope

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// DefaultMaxEnvelopeSize is the cap applied when FillPadding is called with
// a zero or negative maxEnvelopeSize. It matches the default published in
// DISCOVERY.md section 3.1: 25 MB.
const DefaultMaxEnvelopeSize int64 = 25 * 1024 * 1024

// MinEnvelopeSizeBucket is the smallest power-of-two bucket applied to
// envelope wire size (ENVELOPE.md section 2.4.1). Every envelope occupies
// at least this many bytes on the wire.
const MinEnvelopeSizeBucket int64 = 1024

// SelectSizeBucket returns the smallest power-of-two size bucket at least
// as large as unpaddedSize, subject to the floor MinEnvelopeSizeBucket and
// the ceiling maxEnvelopeSize. When maxEnvelopeSize is zero or negative,
// DefaultMaxEnvelopeSize is used.
//
// Reference: ENVELOPE.md section 2.4.1.
func SelectSizeBucket(unpaddedSize int64, maxEnvelopeSize int64) (int64, error) {
	if unpaddedSize < 0 {
		return 0, fmt.Errorf("envelope: negative unpadded size %d", unpaddedSize)
	}
	cap := maxEnvelopeSize
	if cap <= 0 {
		cap = DefaultMaxEnvelopeSize
	}
	if unpaddedSize > cap {
		return 0, fmt.Errorf("envelope: unpadded size %d exceeds max_envelope_size %d", unpaddedSize, cap)
	}
	bucket := MinEnvelopeSizeBucket
	for bucket < unpaddedSize {
		next := bucket << 1
		if next > cap {
			return cap, nil
		}
		bucket = next
	}
	return bucket, nil
}

// FillPadding populates env.Padding with random bytes so that the envelope's
// canonical wire size lands on the power-of-two bucket chosen by
// SelectSizeBucket. It iterates because base64 encoding of padding bytes
// has a non-unit expansion factor and the surrounding JSON structure adds
// constant overhead; a single pass would over- or under-shoot.
//
// FillPadding assumes env.Seal.Signature and env.Seal.SessionMAC are
// already populated to their final on-wire values. Calling FillPadding
// before Sign produces padding keyed to the unsigned envelope's size;
// the signed envelope will be 86 + 42 = 128 characters larger on the
// wire (Ed25519 base64 plus HMAC base64, each growing from "" to its
// full-length form). Call FillPadding after Sign for an exact bucket.
//
// Reference: ENVELOPE.md sections 2.4.2 and 2.4.3.
func FillPadding(env *Envelope, maxEnvelopeSize int64) error {
	if env == nil {
		return errors.New("envelope: nil envelope")
	}
	env.Padding = ""
	for iter := 0; iter < 8; iter++ {
		wire, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("envelope: marshal for padding: %w", err)
		}
		current := int64(len(wire))
		bucket, err := SelectSizeBucket(current, maxEnvelopeSize)
		if err != nil {
			return err
		}
		if current == bucket {
			return nil
		}
		// Padding is a base64 JSON string. Account for the overhead of
		// the JSON string quotes and the base64 expansion factor 4/3.
		// deficit is the number of additional wire bytes required.
		deficit := bucket - current
		// Each byte of padding appended adds 4/3 base64 characters to
		// the `padding` field's encoded length. If env.Padding was
		// previously empty (""), adding N raw bytes replaces "" with a
		// base64 string of ceil(N/3)*4 characters. The string is
		// already enclosed in quotes, so no extra quote accounting.
		//
		// Under-allocate slightly on the first iteration; subsequent
		// iterations converge on the exact bucket.
		raw := deficit * 3 / 4
		if raw <= 0 {
			raw = 1
		}
		// Preserve existing padding budget: the wire serialization above
		// already reflected env.Padding; re-allocate from scratch using
		// the raw total needed to reach the bucket.
		rawTotal, err := rawPaddingBytesFor(env, bucket, maxEnvelopeSize, raw)
		if err != nil {
			return err
		}
		buf := make([]byte, rawTotal)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("envelope: padding rand: %w", err)
		}
		env.Padding = base64.StdEncoding.EncodeToString(buf)
	}
	// After the loop, verify we landed on a bucket. If not, surface an
	// error rather than returning an off-bucket envelope silently.
	wire, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("envelope: marshal final padded: %w", err)
	}
	bucket, err := SelectSizeBucket(int64(len(wire)), maxEnvelopeSize)
	if err != nil {
		return err
	}
	if int64(len(wire)) != bucket {
		return fmt.Errorf("envelope: padding did not converge on bucket %d (got %d)", bucket, len(wire))
	}
	return nil
}

// rawPaddingBytesFor computes the number of raw bytes that, once
// base64-encoded and placed in env.Padding, bring the serialized envelope
// to exactly targetBucket bytes. It runs a few trial serializations and
// applies a correction.
func rawPaddingBytesFor(env *Envelope, targetBucket int64, maxEnvelopeSize int64, seed int64) (int, error) {
	candidate := seed
	for iter := 0; iter < 6; iter++ {
		if candidate < 0 {
			candidate = 0
		}
		buf := make([]byte, candidate)
		env.Padding = base64.StdEncoding.EncodeToString(buf)
		wire, err := json.Marshal(env)
		if err != nil {
			return 0, err
		}
		delta := targetBucket - int64(len(wire))
		if delta == 0 {
			return int(candidate), nil
		}
		// Adjust candidate. Roughly 4 base64 chars per 3 raw bytes.
		candidate += delta * 3 / 4
		if delta > 0 && candidate == seed {
			candidate++
		}
	}
	return int(candidate), nil
}

// PadEnclosureRecipients adds indistinguishable dummy entries to the
// envelope's enclosure_recipients map so that the entry count reaches the
// next power-of-two bucket per ENVELOPE.md section 4.4.1. Buckets: 1, 2,
// 4, 8, ..., 1024.
//
// A dummy entry carries a random 32-byte fingerprint (hex-encoded) and a
// random ciphertext whose length matches a real wrapped key in the map.
// An observer cannot distinguish real from dummy entries without a
// recipient's private key, and legitimate recipients skip dummies because
// their fingerprints do not match any registered public key.
//
// This function does NOT pad brief_recipients. The spec requires brief
// padding to account separately for user-client entries and domain-key
// entries; the current seal.RecipientMap does not tag entries by kind.
// Brief padding is deferred pending a RecipientKey API refinement.
//
// Reference: ENVELOPE.md section 4.4.1.
func PadEnclosureRecipients(s *seal.Seal) error {
	if s == nil {
		return errors.New("envelope: nil seal")
	}
	current := len(s.EnclosureRecipients)
	target := nextPowerOfTwo(current)
	if target <= current {
		return nil
	}
	need := target - current
	rawLen, err := exampleRawWrapLength(s.EnclosureRecipients)
	if err != nil {
		return err
	}
	for i := 0; i < need; i++ {
		fp, err := randomFingerprint()
		if err != nil {
			return err
		}
		ct, err := randomCiphertextB64(rawLen)
		if err != nil {
			return err
		}
		s.EnclosureRecipients[fp] = ct
	}
	return nil
}

// nextPowerOfTwo returns the smallest power of two in [1, 1024] that is
// at least n. Values above 1024 return n unchanged (the bucket is then
// capped at the caller's max; envelopes larger than 1024 recipients fall
// off the obfuscation scheme).
func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	bucket := 1
	for bucket < n {
		bucket <<= 1
		if bucket > 1024 {
			return n
		}
	}
	return bucket
}

// exampleRawWrapLength returns the decoded byte length of a representative
// entry in the map. Used to size dummy ciphertext so it is
// indistinguishable from real wrapped keys. Returns an error if the map
// has no entries to sample.
func exampleRawWrapLength(m seal.RecipientMap) (int, error) {
	for _, v := range m {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return 0, fmt.Errorf("envelope: decode example entry: %w", err)
		}
		return len(raw), nil
	}
	return 0, errors.New("envelope: no example entry in recipient map")
}

// randomFingerprint returns a 32-byte random fingerprint hex-encoded to
// match the keys.Fingerprint wire form. Collision with a real key
// published by any party is 2^-128; treated as negligible.
func randomFingerprint() (keys.Fingerprint, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return keys.Fingerprint(hex.EncodeToString(buf)), nil
}

// randomCiphertextB64 returns a base64 string of n random bytes, matching
// the format used by real wrapped keys.
func randomCiphertextB64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
