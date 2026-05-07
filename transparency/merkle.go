package transparency

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// LeafPrefix and InteriorPrefix are the RFC 6962 domain-separation
// bytes for leaf and interior Merkle node hashing per
// TRANSPARENCY.md §2.2.
const (
	LeafPrefix     byte = 0x00
	InteriorPrefix byte = 0x01
)

// HashLeaf returns SHA-256(0x00 || canonical_json_bytes) per
// TRANSPARENCY.md §2.2 and RFC 6962 §2.1. The canonical bytes are
// the JSON encoding of the LogEntry; the caller MUST use the same
// canonicalization that the log producer used (this library uses
// encoding/json with sorted-by-spec field order).
func HashLeaf(entryBytes []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write(entryBytes)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HashLeafFromEntry marshals entry to canonical JSON and returns
// HashLeaf of the result.
func HashLeafFromEntry(entry LogEntry) ([32]byte, error) {
	bytes, err := json.Marshal(entry)
	if err != nil {
		return [32]byte{}, fmt.Errorf("transparency: marshal log entry: %w", err)
	}
	return HashLeaf(bytes), nil
}

// HashInterior returns SHA-256(0x01 || left || right) per RFC 6962
// §2.1.
func HashInterior(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{InteriorPrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyInclusionProof checks p against rootHash per RFC 6962 §2.1.1.
// Returns nil on a valid proof; otherwise returns a typed error
// the caller surfaces as a transparency-integrity failure.
func VerifyInclusionProof(p InclusionProof, rootHash [32]byte) error {
	if p.LogSize <= 0 {
		return fmt.Errorf("transparency: log_size %d MUST be > 0", p.LogSize)
	}
	if p.LeafIndex < 0 || p.LeafIndex >= p.LogSize {
		return fmt.Errorf("transparency: leaf_index %d out of [0, %d)", p.LeafIndex, p.LogSize)
	}
	leaf, err := decodeHash(p.LeafHash, "leaf_hash")
	if err != nil {
		return err
	}
	siblings, err := decodeHashes(p.Path, "path")
	if err != nil {
		return err
	}
	root, err := computeRootFromInclusion(p.LeafIndex, p.LogSize, leaf, siblings)
	if err != nil {
		return err
	}
	if root != rootHash {
		return errors.New("transparency: computed root does not match STH root_hash")
	}
	return nil
}

// computeRootFromInclusion runs the RFC 6962 inclusion-proof
// recomputation: walks from leaf upward, mixing each sibling on the
// correct side per the leaf-index bit pattern.
func computeRootFromInclusion(leafIndex, treeSize int64, leaf [32]byte, siblings [][32]byte) ([32]byte, error) {
	fn := leafIndex
	sn := treeSize - 1
	r := leaf
	pathIdx := 0
	for sn > 0 {
		if pathIdx >= len(siblings) {
			return [32]byte{}, errors.New("transparency: inclusion proof too short")
		}
		s := siblings[pathIdx]
		pathIdx++
		if (fn & 1) == 1 || fn == sn {
			r = HashInterior(s, r)
			for fn != 0 && (fn&1) == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = HashInterior(r, s)
		}
		fn >>= 1
		sn >>= 1
	}
	if pathIdx != len(siblings) {
		return [32]byte{}, fmt.Errorf("transparency: inclusion proof has %d unused siblings", len(siblings)-pathIdx)
	}
	return r, nil
}

// VerifyConsistencyProof checks p against the two roots per RFC
// 6962 §2.1.2. Returns nil when the proof attests that the tree of
// size FromSize is a prefix of the tree of size ToSize.
func VerifyConsistencyProof(p ConsistencyProof, firstRoot, secondRoot [32]byte) error {
	if p.FromSize < 0 || p.ToSize < 0 {
		return fmt.Errorf("transparency: negative tree size in proof")
	}
	if p.FromSize > p.ToSize {
		return fmt.Errorf("transparency: from_size %d > to_size %d", p.FromSize, p.ToSize)
	}
	if p.FromSize == p.ToSize {
		if len(p.Path) != 0 {
			return errors.New("transparency: consistency proof for equal tree sizes MUST have empty path")
		}
		if firstRoot != secondRoot {
			return errors.New("transparency: equal-size tree roots differ")
		}
		return nil
	}
	if p.FromSize == 0 {
		// Trivially consistent with any later state; the path is
		// expected empty per RFC 6962.
		if len(p.Path) != 0 {
			return errors.New("transparency: consistency proof from size 0 MUST have empty path")
		}
		return nil
	}
	siblings, err := decodeHashes(p.Path, "path")
	if err != nil {
		return err
	}
	gotFirst, gotSecond, err := computeRootsFromConsistency(p.FromSize, p.ToSize, firstRoot, siblings)
	if err != nil {
		return err
	}
	if gotFirst != firstRoot {
		return errors.New("transparency: consistency proof did not reproduce first root")
	}
	if gotSecond != secondRoot {
		return errors.New("transparency: consistency proof did not reproduce second root")
	}
	return nil
}

// computeRootsFromConsistency runs the RFC 6962 §2.1.2 algorithm.
// Returns the recomputed first and second roots given firstSize,
// secondSize, the (already-known) first root that the proof's
// initial seed corresponds to when firstSize is a complete subtree,
// and the proof path.
func computeRootsFromConsistency(firstSize, secondSize int64, firstRoot [32]byte, path [][32]byte) (first, second [32]byte, err error) {
	fn := firstSize - 1
	sn := secondSize - 1
	// Skip subtrees entirely to the left of fn (those whose bottom
	// bit is set; equivalently while fn is odd). RFC 6962 §2.1.2.
	for (fn & 1) == 1 {
		fn >>= 1
		sn >>= 1
	}

	var fr, sr [32]byte
	pathIdx := 0
	if fn != 0 {
		// firstRoot is NOT a complete subtree of secondTree; the
		// proof's first hash seeds the recomputation.
		if pathIdx >= len(path) {
			return [32]byte{}, [32]byte{}, errors.New("transparency: consistency proof too short")
		}
		fr = path[pathIdx]
		sr = path[pathIdx]
		pathIdx++
	} else {
		// firstRoot IS a complete subtree at the front of secondTree.
		// Use it directly as the seed.
		fr = firstRoot
		sr = firstRoot
	}
	for sn > 0 {
		if pathIdx >= len(path) {
			return [32]byte{}, [32]byte{}, errors.New("transparency: consistency proof too short")
		}
		c := path[pathIdx]
		pathIdx++
		if (fn & 1) == 1 || fn == sn {
			fr = HashInterior(c, fr)
			sr = HashInterior(c, sr)
			for fn != 0 && (fn&1) == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = HashInterior(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if pathIdx != len(path) {
		return [32]byte{}, [32]byte{}, fmt.Errorf("transparency: consistency proof has %d unused hashes", len(path)-pathIdx)
	}
	return fr, sr, nil
}

func decodeHash(s string, fieldName string) ([32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("transparency: %s base64: %w", fieldName, err)
	}
	if len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("transparency: %s length %d, want 32", fieldName, len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

func decodeHashes(items []string, fieldName string) ([][32]byte, error) {
	out := make([][32]byte, len(items))
	for i, s := range items {
		h, err := decodeHash(s, fmt.Sprintf("%s[%d]", fieldName, i))
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// LargestPowerOfTwoLessThan returns the largest power of 2 that
// is strictly less than n. Used by RFC 6962 path construction
// (PATH and SUBPROOF) and by computeRootFromInclusion /
// computeRootsFromConsistency.
func LargestPowerOfTwoLessThan(n int64) int64 {
	if n <= 1 {
		return 0
	}
	k := int64(1)
	for k*2 < n {
		k *= 2
	}
	return k
}

// EncodeHash returns the base64 form of h, matching the §3 wire
// representation.
func EncodeHash(h [32]byte) string {
	return base64.StdEncoding.EncodeToString(h[:])
}
