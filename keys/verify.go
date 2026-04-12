package keys

import (
	"encoding/base64"
	"errors"
	"fmt"

	"semp.dev/semp-go/crypto"
)

// Verifier enforces the CLIENT.md §3.3 recipient key validation rules
// on a SEMP_KEYS response before the caller uses any of the returned
// key material for encryption.
//
// Verifier does NOT contact any external source of truth for domain
// keys — it trusts the DomainKey embedded in each ResponseResult as
// the canonical domain signing key for that result's domain. In a
// real deployment the client would cross-check each domain key
// against DNS/DANE or its own pinned copy per KEY.md §5.5 before
// accepting it. This trust-on-first-use model is sufficient for the
// demo but is explicitly documented as a limitation.
type Verifier struct {
	// Suite supplies the signature primitive (Ed25519 for both
	// currently defined SEMP suites).
	Suite crypto.Suite

	// AllowUnsignedRecords, when true, suppresses the
	// "missing domain signature" check on individual user records.
	// The per-record signature check (KEY.md §5.1) is RECOMMENDED
	// but not strictly required because the response-level
	// origin_signature already covers the same material. Tests and
	// early-adopter deployments can disable the per-record check
	// while the server side catches up.
	AllowUnsignedRecords bool
}

// Verify walks every result in resp and enforces CLIENT.md §3.3:
//
//  1. result.OriginSignature is present and verifies against
//     result.DomainKey (the response-level domain signature).
//  2. result.DomainKey is present for every found result (so the
//     client has a domain key to verify against in the first place).
//  3. No returned user Record has a non-nil Revocation. A revoked key
//     MUST NOT be used (KEY.md §8, CLIENT.md §3.3.3).
//  4. For each user Record, if AllowUnsignedRecords is false, there
//     is at least one signature from the result's domain key, and
//     that signature verifies cryptographically.
//
// Results whose Status is not StatusFound are skipped (there's no
// key material to verify). Verify returns the first error
// encountered; a successful call means every found result passed
// all checks and the caller may safely encrypt to any UserKey in
// the response.
func (v *Verifier) Verify(resp *Response) error {
	if v == nil || v.Suite == nil {
		return errors.New("keys: nil verifier or suite")
	}
	if resp == nil {
		return errors.New("keys: nil response")
	}
	signer := v.Suite.Signer()
	for i := range resp.Results {
		r := &resp.Results[i]
		if r.Status != StatusFound {
			continue
		}
		if r.DomainKey == nil {
			return fmt.Errorf("keys: result for %s has no domain_key", r.Address)
		}
		domainPub, err := decodeBase64(r.DomainKey.PublicKey)
		if err != nil {
			return fmt.Errorf("keys: decode domain_key for %s: %w", r.Address, err)
		}
		if err := VerifyResponseResult(signer, r, domainPub); err != nil {
			return fmt.Errorf("keys: %s: %w", r.Address, err)
		}
		domainKeyID := r.DomainKey.KeyID
		for _, rec := range r.UserKeys {
			if rec == nil {
				continue
			}
			if rec.Revocation != nil {
				return fmt.Errorf("keys: user key %s for %s is revoked: %s",
					rec.KeyID, r.Address, rec.Revocation.Reason)
			}
			if v.AllowUnsignedRecords {
				continue
			}
			if err := VerifyRecordSignature(signer, rec, domainKeyID, domainPub); err != nil {
				return fmt.Errorf("keys: user key %s for %s: %w",
					rec.KeyID, r.Address, err)
			}
		}
	}
	return nil
}

// decodeBase64 accepts both standard and URL-safe base64, with or
// without padding. Mirrors the helper in cmd/semp-cli so any key
// response body we receive can be decoded regardless of which
// variant the server used.
func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("keys: not a valid base64 string")
}
