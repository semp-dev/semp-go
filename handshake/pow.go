package handshake

import "time"

// PoWAlgorithm is the only PoW hash algorithm supported by SEMP
// (HANDSHAKE.md §2.2a).
const PoWAlgorithm = "sha256"

// MinPoWPrefixBytes is the minimum entropy required in the PoW challenge
// prefix (HANDSHAKE.md §2.2a).
const MinPoWPrefixBytes = 16

// SolveChallenge searches for a nonce such that:
//
//	SHA-256(prefix || ":" || challengeID || ":" || nonce)
//
// produces a hash with at least difficulty leading zero bits. Returns the
// nonce as base64 and the resulting hash as hex (HANDSHAKE.md §2.2b).
//
// TODO(HANDSHAKE.md §2.2b, REPUTATION.md §8.3.3): implement using
// crypto/sha256 and a random nonce search loop.
func SolveChallenge(prefix []byte, challengeID string, difficulty int, deadline time.Time) (nonceB64, hashHex string, err error) {
	_, _, _, _ = prefix, challengeID, difficulty, deadline
	return "", "", nil
}

// VerifySolution recomputes the PoW hash and confirms it has at least
// difficulty leading zero bits. Servers MUST also confirm that the
// challenge_id has not already been redeemed (REPUTATION.md §8.3.4).
//
// TODO(HANDSHAKE.md §2.2b, REPUTATION.md §8.3.4): implement.
func VerifySolution(prefix []byte, challengeID, nonceB64, claimedHashHex string, difficulty int) error {
	_, _, _, _, _ = prefix, challengeID, nonceB64, claimedHashHex, difficulty
	return nil
}

// LeadingZeroBits returns the count of leading zero bits in hash. Used by
// both the solver and the verifier.
func LeadingZeroBits(hash []byte) int {
	bits := 0
	for _, b := range hash {
		if b == 0 {
			bits += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if b&mask != 0 {
				return bits
			}
			bits++
		}
		return bits
	}
	return bits
}
