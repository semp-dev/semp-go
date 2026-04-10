package handshake

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

// crockfordAlphabet is the Crockford base32 alphabet (RFC 4648 with the
// substitution rules I and L → 1, O → 0). ULIDs are encoded with this
// alphabet, but for our purposes any 26-character base32 string with the
// same total entropy is sufficient — we are only using ULIDs as session
// identifiers, not as RFC 4648 base32 to be parsed by external tools.
//
// We avoid pulling in github.com/oklog/ulid as a dependency just for this
// one helper. The output is a 26-character ULID-shaped string with 48 bits
// of timestamp and 80 bits of randomness.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockfordEncoding = base32.NewEncoding(crockfordAlphabet).WithPadding(base32.NoPadding)

// newULID returns a fresh ULID-shaped string. The first 10 characters encode
// the current Unix millisecond timestamp; the remaining 16 characters are
// random.
//
// This is sufficient for SEMP's session_id requirement, which only demands
// uniqueness per session. We do not need bit-for-bit ULID v0 compliance.
func newULID() (string, error) {
	var raw [16]byte
	now := uint64(time.Now().UnixMilli())
	// 48-bit timestamp in big-endian.
	binary.BigEndian.PutUint64(raw[:8], now<<16)
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", fmt.Errorf("handshake: ulid randomness: %w", err)
	}
	enc := crockfordEncoding.EncodeToString(raw[:])
	if len(enc) > 26 {
		enc = enc[:26]
	}
	return enc, nil
}
