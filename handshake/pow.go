package handshake

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// PoWAlgorithm is the only PoW hash algorithm supported by SEMP
// (HANDSHAKE.md §2.2a).
const PoWAlgorithm = "sha256"

// MinPoWPrefixBytes is the minimum entropy required in the PoW challenge
// prefix (HANDSHAKE.md §2.2a).
const MinPoWPrefixBytes = 16

// powPreimage constructs the byte sequence that the PoW hash is computed over
// (VECTORS.md §4.3):
//
//	base64(prefix) + ":" + challenge_id + ":" + base64(nonce)
//
// All three components are UTF-8 strings; the colons are literal `:` bytes.
// nonceB64 is provided already base64-encoded so the same helper can be used
// by both the solver (which generates raw nonces) and the verifier (which
// receives a base64 nonce on the wire).
func powPreimage(prefix []byte, challengeID, nonceB64 string) []byte {
	prefixB64 := base64.StdEncoding.EncodeToString(prefix)
	// Use a single allocation: len = prefixB64 + 1 + len(challengeID) + 1 + len(nonceB64)
	out := make([]byte, 0, len(prefixB64)+len(challengeID)+len(nonceB64)+2)
	out = append(out, prefixB64...)
	out = append(out, ':')
	out = append(out, challengeID...)
	out = append(out, ':')
	out = append(out, nonceB64...)
	return out
}

// SolveChallenge searches for a nonce such that:
//
//	SHA-256(base64(prefix) || ":" || challengeID || ":" || base64(nonce))
//
// produces a hash with at least difficulty leading zero bits. Returns the
// nonce as base64 and the resulting hash as hex (HANDSHAKE.md §2.2b,
// VECTORS.md §4.3).
//
// The search walks an 8-byte big-endian counter starting from 0. Difficulty
// 16 typically resolves in well under a million iterations; difficulty 20 in
// well under sixteen million. If deadline is non-zero and is reached before
// a solution is found, SolveChallenge returns an error.
func SolveChallenge(prefix []byte, challengeID string, difficulty int, deadline time.Time) (nonceB64, hashHex string, err error) {
	if difficulty < 0 {
		return "", "", errors.New("handshake: negative PoW difficulty")
	}
	if difficulty > 256 {
		return "", "", errors.New("handshake: PoW difficulty exceeds SHA-256 output size")
	}
	if challengeID == "" {
		return "", "", errors.New("handshake: empty PoW challenge_id")
	}
	if len(prefix) < MinPoWPrefixBytes {
		// The spec REQUIRES at least 16 bytes of entropy in the prefix
		// (HANDSHAKE.md §2.2a). Solving against a shorter prefix would
		// produce a solution the spec-conformant verifier would reject.
		return "", "", errors.New("handshake: PoW prefix below minimum entropy")
	}
	var counterBuf [8]byte
	checkDeadline := !deadline.IsZero()
	for counter := uint64(0); ; counter++ {
		// Check the deadline once every 65,536 iterations to keep the inner
		// loop tight. SHA-256 is the dominant cost; the time check is rare.
		if checkDeadline && counter&0xFFFF == 0 && time.Now().After(deadline) {
			return "", "", errors.New("handshake: PoW deadline exceeded")
		}
		binary.BigEndian.PutUint64(counterBuf[:], counter)
		nonce := base64.StdEncoding.EncodeToString(counterBuf[:])
		pre := powPreimage(prefix, challengeID, nonce)
		sum := sha256.Sum256(pre)
		if LeadingZeroBits(sum[:]) >= difficulty {
			return nonce, hex.EncodeToString(sum[:]), nil
		}
		if counter == ^uint64(0) {
			return "", "", errors.New("handshake: PoW search space exhausted")
		}
	}
}

// VerifySolution recomputes the PoW hash and confirms it has at least
// difficulty leading zero bits and that it matches the claimed hash.
//
// VerifySolution does NOT check challenge replay (whether challenge_id has
// been redeemed before) — that is the responsibility of the calling server,
// which holds the challenge ledger. Per REPUTATION.md §8.3.4 servers MUST
// reject duplicate challenge_id submissions even when the solution is
// arithmetically valid.
//
// Reference: HANDSHAKE.md §2.2b, VECTORS.md §4.1, §4.2.
func VerifySolution(prefix []byte, challengeID, nonceB64, claimedHashHex string, difficulty int) error {
	if difficulty < 0 {
		return errors.New("handshake: negative PoW difficulty")
	}
	if challengeID == "" {
		return errors.New("handshake: empty PoW challenge_id")
	}
	if nonceB64 == "" {
		return errors.New("handshake: empty PoW nonce")
	}
	if _, err := base64.StdEncoding.DecodeString(nonceB64); err != nil {
		return errors.New("handshake: PoW nonce is not valid base64")
	}
	pre := powPreimage(prefix, challengeID, nonceB64)
	sum := sha256.Sum256(pre)
	computed := hex.EncodeToString(sum[:])
	if !strings.EqualFold(computed, claimedHashHex) {
		return errors.New("handshake: PoW hash mismatch")
	}
	if LeadingZeroBits(sum[:]) < difficulty {
		return errors.New("handshake: PoW insufficient difficulty")
	}
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
