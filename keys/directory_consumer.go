package keys

import (
	"errors"
	"fmt"
	"sync"

	"github.com/semp-dev/semp-go/crypto"
)

// DirectoryCache is the consumer-side state required by KEY.md
// §10.6.2 rollback detection: a per-(user_id) record of the
// highest directory revision the consumer has accepted. A fetched
// directory whose `revision` is less than the cached value MUST be
// treated with the same suspicion as a key-substitution attempt.
//
// DirectoryCache is concurrency-safe; concurrent verifiers see
// each other's updates atomically.
type DirectoryCache struct {
	mu      sync.Mutex
	highest map[string]int64 // user_id -> highest accepted revision
}

// NewDirectoryCache returns an empty cache.
func NewDirectoryCache() *DirectoryCache {
	return &DirectoryCache{highest: make(map[string]int64)}
}

// VerifyAndCache runs every §10.6.3 consumer rule on dir and, on
// success, advances the cached revision for dir.UserID. Returns
// nil when the directory is acceptable; otherwise returns a typed
// error the caller surfaces.
//
// Steps run in order so the most-fundamental failures surface
// first:
//
//  1. Schema validation (every device_id unique, every entry's
//     role/certificate_id consistent, revision >= 1).
//  2. Identity-key signature verification under userIdentityPub.
//  3. Rollback check against the cached highest revision.
//  4. Optional certificate-presence callback per entry with
//     role: "delegated".
//
// CertCheck MAY be nil; passing nil disables the §10.6.3
// "delegated entries' scoped certificate is published and
// unexpired" check (useful for tests, partial deployments, and the
// §10.6 interface where the certificate store lives in a separate
// component).
func (c *DirectoryCache) VerifyAndCache(suite crypto.Suite, dir *DeviceDirectory, userIdentityPub []byte, certCheck CertificateCheck) error {
	if dir == nil {
		return errors.New("keys: directory cache verify nil directory")
	}
	if err := dir.Validate(); err != nil {
		return err
	}
	if len(userIdentityPub) == 0 {
		return errors.New("keys: directory cache verify missing identity public key")
	}
	if err := VerifyDeviceDirectory(suite.Signer(), userIdentityPub, dir); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.highest[dir.UserID]; ok && dir.Revision < cached {
		return fmt.Errorf("keys: directory revision %d for %s is less than cached revision %d (rollback suspected per KEY.md §10.6.2)",
			dir.Revision, dir.UserID, cached)
	}
	if certCheck != nil {
		for _, entry := range dir.Devices {
			if entry.Role != DeviceRoleDelegated {
				continue
			}
			if entry.CertificateID == nil {
				continue
			}
			if err := certCheck(*entry.CertificateID); err != nil {
				return fmt.Errorf("keys: directory delegated entry %s: %w", entry.DeviceID, err)
			}
		}
	}
	c.highest[dir.UserID] = dir.Revision
	return nil
}

// Highest returns the highest accepted revision for userID, or 0
// if none is cached.
func (c *DirectoryCache) Highest(userID string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.highest[userID]
}

// Reset clears the cached entry for userID. Intended for tests and
// for operator-driven manual overrides; production consumers MUST
// NOT reset cached revisions absent strong evidence the prior
// cache was poisoned.
func (c *DirectoryCache) Reset(userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.highest, userID)
}

// CertificateCheck is invoked for each delegated entry in a fetched
// directory. Implementations look up the certificate by id and
// confirm it is published and unexpired per KEY.md §10.6.3 and
// §10.3.8. Returning a non-nil error fails directory verification
// for that entry.
type CertificateCheck func(certificateID string) error
