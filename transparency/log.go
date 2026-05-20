package transparency

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"semp.dev/semp-go/crypto"
)

// LogConfig bundles inputs to NewLog.
type LogConfig struct {
	// DomainKeyID + DomainPriv sign every issued STH.
	DomainKeyID string
	DomainPriv  []byte

	// Suite supplies the signer for STH signatures.
	Suite crypto.Suite

	// NowFn provides the wall-clock for STH timestamps. Defaults to
	// time.Now().UTC.
	NowFn func() time.Time
}

// Log is the operator-runnable transparency log state machine.
// Maintains an append-only sequence of leaf hashes, issues
// SignedTreeHeads, and computes RFC 6962 inclusion + consistency
// proofs against the current state.
//
// Log is concurrency-safe: Append and IssueSTH are exclusive of one
// another; read methods (Size, Entry, InclusionProof,
// ConsistencyProof) take a read lock and may run concurrently.
//
// The reference implementation holds entries and leaf hashes in
// memory. Production deployments wrap a durable backend; the Log's
// operations are clean enough to factor into a Store interface
// when that becomes necessary.
type Log struct {
	mu      sync.RWMutex
	entries []LogEntry
	leaves  [][32]byte

	cfg LogConfig
}

// NewLog returns a fresh empty Log.
func NewLog(cfg LogConfig) (*Log, error) {
	if cfg.Suite == nil {
		return nil, errors.New("transparency: log requires Suite")
	}
	if cfg.DomainKeyID == "" || len(cfg.DomainPriv) == 0 {
		return nil, errors.New("transparency: log requires DomainKeyID and DomainPriv")
	}
	if cfg.NowFn == nil {
		cfg.NowFn = func() time.Time { return time.Now().UTC() }
	}
	return &Log{cfg: cfg}, nil
}

// Append validates entry, hashes its leaf, and appends to the log.
// Returns the assigned leaf index (0-based).
//
// Append does NOT verify any signature on entry; the caller's
// admission policy decides which entries are accepted. Once
// appended, an entry is part of the log permanently.
func (l *Log) Append(_ context.Context, entry LogEntry) (int64, error) {
	if err := entry.Validate(); err != nil {
		return 0, fmt.Errorf("transparency: append validate: %w", err)
	}
	leaf, err := HashLeafFromEntry(entry)
	if err != nil {
		return 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, entry)
	l.leaves = append(l.leaves, leaf)
	return int64(len(l.leaves) - 1), nil
}

// Size returns the current tree size.
func (l *Log) Size() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return int64(len(l.leaves))
}

// Entry returns a defensive copy of the entry at index, or
// ErrEntryNotFound when index is out of range.
func (l *Log) Entry(_ context.Context, index int64) (LogEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index < 0 || index >= int64(len(l.entries)) {
		return LogEntry{}, ErrEntryNotFound
	}
	return l.entries[index], nil
}

// IssueSTH computes the current root hash and returns a signed
// tree head. The STH's timestamp is set from NowFn.
func (l *Log) IssueSTH(_ context.Context) (*SignedTreeHead, error) {
	l.mu.RLock()
	leaves := append([][32]byte(nil), l.leaves...)
	l.mu.RUnlock()

	root := subtreeRoot(leaves)
	sth := &SignedTreeHead{
		LogSize:   int64(len(leaves)),
		RootHash:  EncodeHash(root),
		Timestamp: l.cfg.NowFn(),
	}
	if err := SignSTH(l.cfg.Suite.Signer(), l.cfg.DomainPriv, l.cfg.DomainKeyID, sth); err != nil {
		return nil, fmt.Errorf("transparency: sign STH: %w", err)
	}
	return sth, nil
}

// InclusionProof computes an RFC 6962 audit path for leafIndex
// against treeSize. Returns ErrInvalidIndex when leafIndex >=
// treeSize; ErrInvalidTreeSize when treeSize > current Size.
func (l *Log) InclusionProof(_ context.Context, leafIndex, treeSize int64) (*InclusionProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if treeSize <= 0 {
		return nil, ErrInvalidTreeSize
	}
	if int64(len(l.leaves)) < treeSize {
		return nil, ErrInvalidTreeSize
	}
	if leafIndex < 0 || leafIndex >= treeSize {
		return nil, ErrInvalidIndex
	}
	leaves := l.leaves[:treeSize]
	siblings := auditPath(int(leafIndex), leaves)
	return &InclusionProof{
		LeafIndex: leafIndex,
		LogSize:   treeSize,
		LeafHash:  EncodeHash(leaves[leafIndex]),
		Path:      hashSliceToBase64(siblings),
	}, nil
}

// ConsistencyProof returns an RFC 6962 consistency proof from
// firstSize to secondSize. Both MUST be in (0, current Size];
// firstSize MUST be <= secondSize.
func (l *Log) ConsistencyProof(_ context.Context, firstSize, secondSize int64) (*ConsistencyProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if firstSize <= 0 || secondSize <= 0 {
		return nil, ErrInvalidTreeSize
	}
	if firstSize > secondSize {
		return nil, ErrInvalidTreeSize
	}
	if secondSize > int64(len(l.leaves)) {
		return nil, ErrInvalidTreeSize
	}
	second := l.leaves[:secondSize]
	path := Subproof(int(firstSize), second, true)
	return &ConsistencyProof{
		FromSize: firstSize,
		ToSize:   secondSize,
		Path:     hashSliceToBase64(path),
	}, nil
}

// Sentinel errors.
var (
	// ErrEntryNotFound is returned by Entry when the index is out
	// of range.
	ErrEntryNotFound = errors.New("transparency: entry not found")

	// ErrInvalidIndex is returned by InclusionProof when leafIndex
	// is out of range for treeSize.
	ErrInvalidIndex = errors.New("transparency: leaf_index out of range")

	// ErrInvalidTreeSize is returned by InclusionProof and
	// ConsistencyProof when treeSize is zero, exceeds the current
	// log, or violates ordering (firstSize > secondSize).
	ErrInvalidTreeSize = errors.New("transparency: invalid tree_size")
)

// subtreeRoot computes MTH(D[0:n]) per RFC 6962 §2.1. An empty
// slice returns the all-zeros hash (the spec defines MTH for an
// empty list as SHA-256(empty), but inclusion / consistency
// proofs never operate on an empty subtree directly).
func subtreeRoot(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return [32]byte{}
	case 1:
		return leaves[0]
	}
	k := LargestPowerOfTwoLessThan(int64(len(leaves)))
	left := subtreeRoot(leaves[:k])
	right := subtreeRoot(leaves[k:])
	return HashInterior(left, right)
}

// auditPath computes PATH(m, D[0:n]) per RFC 6962 §2.1.1.
func auditPath(m int, leaves [][32]byte) [][32]byte {
	n := len(leaves)
	if n == 0 {
		return nil
	}
	if n == 1 {
		return nil
	}
	k := int(LargestPowerOfTwoLessThan(int64(n)))
	if m < k {
		return append(auditPath(m, leaves[:k]), subtreeRoot(leaves[k:]))
	}
	return append(auditPath(m-k, leaves[k:]), subtreeRoot(leaves[:k]))
}

// Subproof computes SUBPROOF(m, D[0:n], b) per RFC 6962 §2.1.2.
// The PROOF(m, D[n]) used for consistency is SUBPROOF(m, D[0:n], true).
func Subproof(m int, leaves [][32]byte, b bool) [][32]byte {
	n := len(leaves)
	if m == n {
		if b {
			return nil
		}
		return [][32]byte{subtreeRoot(leaves)}
	}
	k := int(LargestPowerOfTwoLessThan(int64(n)))
	if m <= k {
		return append(Subproof(m, leaves[:k], b), subtreeRoot(leaves[k:]))
	}
	return append(Subproof(m-k, leaves[k:], false), subtreeRoot(leaves[:k]))
}

// hashSliceToBase64 returns a slice of base64-encoded hashes
// (the wire form used in InclusionProof.Siblings and
// ConsistencyProof.Path).
func hashSliceToBase64(hashes [][32]byte) []string {
	out := make([]string, len(hashes))
	for i, h := range hashes {
		out[i] = base64.StdEncoding.EncodeToString(h[:])
	}
	return out
}

// MarshalEntries returns canonical JSON for a slice of entries -
// useful for log mirroring or audit-monitor batch fetches.
func MarshalEntries(entries []LogEntry) ([]byte, error) {
	return json.Marshal(entries)
}
