package keys

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/internal/canonical"
)

// SignatureAlgorithmEd25519 is the algorithm string used in
// Signature.Algorithm for Ed25519 signatures — the only algorithm
// used for key-layer signatures in both currently defined SEMP
// suites (ENVELOPE.md §7.3.1).
const SignatureAlgorithmEd25519 = "ed25519"

// canonicalRecordBytes returns the canonical JSON form of rec with the
// `signatures` and `revocation` fields elided. This is the byte
// sequence over which per-record signatures (KEY.md §5) are computed,
// so that adding a signature does not invalidate signatures already
// present and so that a revocation attached after signing does not
// either.
func canonicalRecordBytes(rec *Record) ([]byte, error) {
	if rec == nil {
		return nil, errors.New("keys: nil record")
	}
	return canonical.MarshalWithElision(rec, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("keys: expected top-level object, got %T", v)
		}
		delete(m, "signatures")
		delete(m, "revocation")
		return nil
	})
}

// SignRecord computes a signature over the canonical form of rec
// (with signatures and revocation elided) using privKey, and appends
// the resulting Signature to rec.Signatures. Used by the serving
// home server to produce the domain signature on a user key record
// (KEY.md §5.1), and optionally by the user's client to produce a
// self-signature (KEY.md §5.2).
func SignRecord(signer crypto.Signer, privKey []byte, signerAddr string, signerKeyID Fingerprint, rec *Record) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if rec == nil {
		return errors.New("keys: nil record")
	}
	if len(privKey) == 0 {
		return errors.New("keys: empty signer private key")
	}
	msg, err := canonicalRecordBytes(rec)
	if err != nil {
		return fmt.Errorf("keys: canonical record: %w", err)
	}
	sigBytes, err := signer.Sign(privKey, msg)
	if err != nil {
		return fmt.Errorf("keys: sign record: %w", err)
	}
	rec.Signatures = append(rec.Signatures, Signature{
		Signer:    signerAddr,
		KeyID:     signerKeyID,
		Value:     base64.StdEncoding.EncodeToString(sigBytes),
		Timestamp: time.Now().UTC(),
	})
	return nil
}

// VerifyRecordSignature verifies that rec.Signatures contains a valid
// signature with the given signerKeyID, using signerPub as the public
// key. Returns nil on success, or an error if no matching signature
// is present, if the signature bytes fail to decode, or if the
// cryptographic verification fails.
func VerifyRecordSignature(signer crypto.Signer, rec *Record, signerKeyID Fingerprint, signerPub []byte) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if rec == nil {
		return errors.New("keys: nil record")
	}
	if len(signerPub) == 0 {
		return errors.New("keys: empty signer public key")
	}
	var found *Signature
	for i := range rec.Signatures {
		if rec.Signatures[i].KeyID == signerKeyID {
			found = &rec.Signatures[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("keys: no signature from key %s on record %s", signerKeyID, rec.KeyID)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(found.Value)
	if err != nil {
		return fmt.Errorf("keys: signature base64: %w", err)
	}
	msg, err := canonicalRecordBytes(rec)
	if err != nil {
		return fmt.Errorf("keys: canonical record: %w", err)
	}
	if err := signer.Verify(signerPub, msg, sigBytes); err != nil {
		return fmt.Errorf("keys: verify record signature: %w", err)
	}
	return nil
}

// canonicalResponseResultBytes returns the canonical JSON form of r
// with the `origin_signature` field elided. This is the byte
// sequence over which OriginSignature is computed per CLIENT.md
// §5.4.5 / KEY.md §4.3 (the "response-level" domain signature).
func canonicalResponseResultBytes(r *ResponseResult) ([]byte, error) {
	if r == nil {
		return nil, errors.New("keys: nil response result")
	}
	return canonical.MarshalWithElision(r, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("keys: expected top-level object, got %T", v)
		}
		delete(m, "origin_signature")
		return nil
	})
}

// SignResponseResult fills in r.OriginSignature with a domain
// signature over the canonical bytes of r, computed with privKey.
// Used by the serving home server when returning a local lookup
// result from inboxd.handleKeys. The origin_signature is an end-to-
// end attestation: a home server that forwards this result to its
// own client via federation MUST pass the origin_signature through
// intact (CLIENT.md §5.4.5).
func SignResponseResult(signer crypto.Signer, privKey []byte, keyID Fingerprint, r *ResponseResult) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if r == nil {
		return errors.New("keys: nil response result")
	}
	if len(privKey) == 0 {
		return errors.New("keys: empty signer private key")
	}
	msg, err := canonicalResponseResultBytes(r)
	if err != nil {
		return fmt.Errorf("keys: canonical response result: %w", err)
	}
	sigBytes, err := signer.Sign(privKey, msg)
	if err != nil {
		return fmt.Errorf("keys: sign response result: %w", err)
	}
	r.OriginSignature = &Signature{
		Signer:    r.Domain,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(sigBytes),
		Timestamp: time.Now().UTC(),
	}
	return nil
}

// VerifyResponseResult verifies r.OriginSignature against the given
// domain public key. Returns an error if OriginSignature is missing,
// if the signature bytes fail to decode, or if the cryptographic
// verification fails. The caller is responsible for deciding which
// public key to use; typically the client passes r.DomainKey.PublicKey
// (self-attested) or a value cross-checked against DNS/DANE.
func VerifyResponseResult(signer crypto.Signer, r *ResponseResult, domainPub []byte) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if r == nil {
		return errors.New("keys: nil response result")
	}
	if r.OriginSignature == nil {
		return errors.New("keys: response result has no origin_signature")
	}
	if len(domainPub) == 0 {
		return errors.New("keys: empty domain public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(r.OriginSignature.Value)
	if err != nil {
		return fmt.Errorf("keys: origin_signature base64: %w", err)
	}
	msg, err := canonicalResponseResultBytes(r)
	if err != nil {
		return fmt.Errorf("keys: canonical response result: %w", err)
	}
	if err := signer.Verify(domainPub, msg, sigBytes); err != nil {
		return fmt.Errorf("keys: verify origin_signature: %w", err)
	}
	return nil
}
