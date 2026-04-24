package envelope

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// base64AlphabetFillers is the pool of single characters used to
// extend a base64 string by 1, 2, or 3 bytes when the bucket target
// requires non-multiple-of-4 padding length. ENVELOPE.md section 2.4.2
// permits appending 1 to 3 additional base64-alphabet characters to
// an otherwise valid base64 encoding for bucket alignment.
const base64AlphabetFillers = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// DefaultMaxEnvelopeSize is the cap applied when FillPadding is called with
// a zero or negative maxEnvelopeSize. It matches the default published in
// DISCOVERY.md section 3.1: 25 MB.
const DefaultMaxEnvelopeSize int64 = 25 * 1024 * 1024

// MinEnvelopeSizeBucket is the smallest power-of-two bucket applied to
// envelope wire size (ENVELOPE.md section 2.4.1 and 2.4.4). Every
// envelope occupies at least this many bytes on the wire. Raised from
// 1 KB to 4 KB in spec commit 298ae6b because the 1 KB floor never
// actually bound any real envelope.
const MinEnvelopeSizeBucket int64 = 4096

// Ed25519SignatureB64Len is the exact length in characters of a
// base64-encoded Ed25519 signature (64 raw bytes -> 88 base64 chars).
// FillPadding uses this to reserve space in the envelope before
// signing so the signature, which grows from "" to its full form at
// Sign time, does not push the envelope past its target bucket.
const Ed25519SignatureB64Len = 88

// HMACSHA256B64Len is the exact length in characters of a
// base64-encoded HMAC-SHA-256 output (32 raw bytes -> 44 base64 chars).
// Used the same way as Ed25519SignatureB64Len for the session MAC
// field.
const HMACSHA256B64Len = 44

// SelectSizeBucket returns the smallest bucket at least as large as
// unpaddedSize, subject to the floor MinEnvelopeSizeBucket and the
// ceiling maxEnvelopeSize. When maxEnvelopeSize is zero or negative,
// DefaultMaxEnvelopeSize is used. Uses the default power-of-two
// sequence; for a custom sequence use SelectSizeBucketFrom.
//
// Reference: ENVELOPE.md section 2.4.1.
func SelectSizeBucket(unpaddedSize int64, maxEnvelopeSize int64) (int64, error) {
	return SelectSizeBucketFrom(unpaddedSize, maxEnvelopeSize, nil)
}

// SelectSizeBucketFrom is like SelectSizeBucket but accepts a custom
// bucket sequence. When sequence is nil or empty, the default
// power-of-two curve starting at MinEnvelopeSizeBucket is used.
//
// Custom sequences MUST be monotonically strictly increasing, with
// the first element at or above MinEnvelopeSizeBucket and the last
// element at or below the effective max_envelope_size. Operator
// deployments may tune the curve (for example, 1.5x steps instead of
// 2x) to trade bandwidth overhead against bucket distinguishability
// per ENVELOPE.md section 2.4.1.
func SelectSizeBucketFrom(unpaddedSize int64, maxEnvelopeSize int64, sequence []int64) (int64, error) {
	if unpaddedSize < 0 {
		return 0, fmt.Errorf("envelope: negative unpadded size %d", unpaddedSize)
	}
	ceiling := maxEnvelopeSize
	if ceiling <= 0 {
		ceiling = DefaultMaxEnvelopeSize
	}
	if unpaddedSize > ceiling {
		return 0, fmt.Errorf("envelope: unpadded size %d exceeds max_envelope_size %d", unpaddedSize, ceiling)
	}
	if len(sequence) > 0 {
		if err := validateBucketSequence(sequence, ceiling); err != nil {
			return 0, err
		}
		for _, b := range sequence {
			if b >= unpaddedSize {
				return b, nil
			}
		}
		// Fell off the end of the custom sequence; clamp to the
		// ceiling per ENVELOPE.md section 2.4.1.
		return ceiling, nil
	}
	bucket := MinEnvelopeSizeBucket
	for bucket < unpaddedSize {
		next := bucket << 1
		if next > ceiling {
			return ceiling, nil
		}
		bucket = next
	}
	return bucket, nil
}

func validateBucketSequence(seq []int64, ceiling int64) error {
	if seq[0] < MinEnvelopeSizeBucket {
		return fmt.Errorf("envelope: bucket sequence first element %d is below protocol floor %d",
			seq[0], MinEnvelopeSizeBucket)
	}
	for i := 1; i < len(seq); i++ {
		if seq[i] <= seq[i-1] {
			return fmt.Errorf("envelope: bucket sequence is not strictly increasing at index %d", i)
		}
	}
	if seq[len(seq)-1] > ceiling {
		return fmt.Errorf("envelope: bucket sequence last element %d exceeds max_envelope_size %d",
			seq[len(seq)-1], ceiling)
	}
	return nil
}

// PadConfig controls FillPadding behavior.
type PadConfig struct {
	// MaxEnvelopeSize is the session-negotiated ceiling. Zero means
	// DefaultMaxEnvelopeSize.
	MaxEnvelopeSize int64

	// BucketSequence, if non-empty, overrides the default power-of-two
	// bucket sequence. Must satisfy validateBucketSequence. Operators
	// tune this per ENVELOPE.md section 2.4.1 "Operator tuning".
	BucketSequence []int64
}

// FillPadding populates env.Padding with a string whose length brings
// the serialized envelope's wire size exactly onto the bucket chosen
// from the configured sequence. It is safe to call either before Sign
// (pre-sign flow: temporarily fills the signature and MAC with
// fixed-length placeholders so the bucket math is exact) or after Sign
// (post-sign flow: the real signature and MAC already occupy their
// final lengths). Either way, the final on-wire size matches the
// selected bucket.
//
// The padding value is base64-alphabet filler per ENVELOPE.md section
// 2.4.2: base64-encoded CSPRNG bytes, optionally extended by 1 to 3
// additional base64-alphabet characters (drawn from the same CSPRNG
// byte stream) to reach a bucket that base64's 4-character granularity
// could not otherwise hit.
//
// Reference: ENVELOPE.md sections 2.4.1 through 2.4.3.
func FillPadding(env *Envelope, cfg PadConfig) error {
	if env == nil {
		return errors.New("envelope: nil envelope")
	}

	// Temporarily substitute placeholder signature and MAC of the
	// right length so the serialized size reflects the final wire
	// form even when the caller has not yet signed. Record the
	// previous values so we can restore them afterward (the signer
	// will overwrite them with real values if the envelope is
	// still unsigned).
	origSig := env.Seal.Signature
	origMAC := env.Seal.SessionMAC
	if origSig == "" {
		env.Seal.Signature = strings.Repeat("A", Ed25519SignatureB64Len)
	}
	if origMAC == "" {
		env.Seal.SessionMAC = strings.Repeat("A", HMACSHA256B64Len)
	}
	defer func() {
		if origSig == "" {
			env.Seal.Signature = ""
		}
		if origMAC == "" {
			env.Seal.SessionMAC = ""
		}
	}()

	// Measure the wire size with env.Padding set to the empty string.
	// From this baseline, any target bucket translates into a target
	// padding-value length via a simple byte-for-byte accounting.
	env.Padding = ""
	baseline, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("envelope: marshal baseline: %w", err)
	}
	baseSize := int64(len(baseline))
	bucket, err := SelectSizeBucketFrom(baseSize, cfg.MaxEnvelopeSize, cfg.BucketSequence)
	if err != nil {
		return err
	}
	if baseSize == bucket {
		return nil
	}
	targetPadLen := bucket - baseSize
	if targetPadLen < 0 {
		return fmt.Errorf("envelope: baseline %d exceeds bucket %d", baseSize, bucket)
	}

	padValue, err := buildPaddingValue(int(targetPadLen))
	if err != nil {
		return fmt.Errorf("envelope: build padding: %w", err)
	}
	env.Padding = padValue

	// Final assertion: the envelope now marshals to exactly bucket.
	wire, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("envelope: marshal final padded: %w", err)
	}
	if int64(len(wire)) != bucket {
		return fmt.Errorf("envelope: padding did not land on bucket %d (got %d)", bucket, len(wire))
	}
	return nil
}

// buildPaddingValue returns a string of exactly targetLen characters
// drawn from the base64 alphabet. The bulk of the string is a proper
// base64 encoding of CSPRNG bytes; the final 1 to 3 characters (when
// targetLen is not a multiple of 4 that is reachable by StdEncoding)
// are CSPRNG-seeded alphabet characters appended for length alignment.
//
// Per ENVELOPE.md section 2.4.2, the string is opaque filler; no party
// decodes it.
func buildPaddingValue(targetLen int) (string, error) {
	if targetLen < 0 {
		return "", fmt.Errorf("negative padding length %d", targetLen)
	}
	if targetLen == 0 {
		return "", nil
	}
	// base64.StdEncoding emits 4 characters per 3 input bytes; shorter
	// outputs (1-3 chars) are not achievable. Compute the largest
	// multiple-of-4 length at or below targetLen, then append 1-3
	// alphabet fillers to close the gap.
	b64Len := (targetLen / 4) * 4
	filler := targetLen - b64Len
	if filler != 0 && b64Len == 0 {
		// targetLen < 4; everything must be filler.
		b64Len = 0
		filler = targetLen
	}
	var b strings.Builder
	b.Grow(targetLen)
	if b64Len > 0 {
		raw := (b64Len / 4) * 3
		buf := make([]byte, raw)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("rand for base64 body: %w", err)
		}
		b.WriteString(base64.StdEncoding.EncodeToString(buf))
	}
	if filler > 0 {
		seed := make([]byte, filler)
		if _, err := rand.Read(seed); err != nil {
			return "", fmt.Errorf("rand for filler: %w", err)
		}
		for i := 0; i < filler; i++ {
			b.WriteByte(base64AlphabetFillers[int(seed[i])&63])
		}
	}
	return b.String(), nil
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
