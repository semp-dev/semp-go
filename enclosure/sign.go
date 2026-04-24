package enclosure

import (
	"encoding/base64"
	"errors"
	"fmt"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/internal/canonical"
)

// SignatureAlgorithmEd25519 is the only signature algorithm defined
// for enclosure-layer signatures in the current spec.
const SignatureAlgorithmEd25519 = "ed25519"

// SignEnclosure populates enc.SenderSignature with an Ed25519 signature
// by the sender's identity key over the canonical enclosure bytes per
// ENVELOPE.md section 6.5.2.
//
// Canonicalization sets sender_signature.value to "" during signing.
// Every other field of the enclosure (including forwarded_from) is
// covered, so the signature binds the full content the recipient will
// eventually decrypt.
//
// SignEnclosure overwrites any existing SenderSignature. Call it after
// the enclosure is fully composed (body, attachments, forwarded_from,
// extensions all set) and before encryption.
func SignEnclosure(enc *Enclosure, suite crypto.Suite, identityPrivateKey []byte, identityKeyID string) error {
	if enc == nil {
		return errors.New("enclosure: nil enclosure")
	}
	if suite == nil {
		return errors.New("enclosure: nil suite")
	}
	if len(identityPrivateKey) == 0 {
		return errors.New("enclosure: empty identity private key")
	}
	if identityKeyID == "" {
		return errors.New("enclosure: empty identity key_id")
	}
	enc.SenderSignature = &Signature{
		Algorithm: SignatureAlgorithmEd25519,
		KeyID:     identityKeyID,
		Value:     "",
	}
	canonicalBytes, err := canonical.MarshalWithElision(enc, canonical.EnclosureElider())
	if err != nil {
		return fmt.Errorf("enclosure: canonical bytes: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxEnclosureSender, canonicalBytes)
	sig, err := suite.Signer().Sign(identityPrivateKey, prefixed)
	if err != nil {
		return fmt.Errorf("enclosure: sign: %w", err)
	}
	enc.SenderSignature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyEnclosureSignature confirms that enc.SenderSignature was
// produced by identityPublicKey over the canonical enclosure bytes.
// Returns nil on successful verification, an error otherwise.
//
// Callers are responsible for obtaining the correct identityPublicKey
// from the sender's published key set (KEY.md section 3). Looking up
// the key by enc.SenderSignature.KeyID is the conventional path.
func VerifyEnclosureSignature(enc *Enclosure, suite crypto.Suite, identityPublicKey []byte) error {
	if enc == nil {
		return errors.New("enclosure: nil enclosure")
	}
	if suite == nil {
		return errors.New("enclosure: nil suite")
	}
	if enc.SenderSignature == nil {
		return errors.New("enclosure: missing sender_signature")
	}
	if enc.SenderSignature.Algorithm != SignatureAlgorithmEd25519 {
		return fmt.Errorf("enclosure: unsupported sender_signature algorithm %q", enc.SenderSignature.Algorithm)
	}
	claimedSig, err := base64.StdEncoding.DecodeString(enc.SenderSignature.Value)
	if err != nil {
		return fmt.Errorf("enclosure: sender_signature value base64: %w", err)
	}
	// Reconstruct canonical bytes: recompute with sender_signature.value
	// elided to "". This is the same form SignEnclosure signed over.
	canonicalBytes, err := canonical.MarshalWithElision(enc, canonical.EnclosureElider())
	if err != nil {
		return fmt.Errorf("enclosure: canonical bytes: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxEnclosureSender, canonicalBytes)
	if err := suite.Signer().Verify(identityPublicKey, prefixed, claimedSig); err != nil {
		return fmt.Errorf("enclosure: sender_signature verify: %w", err)
	}
	return nil
}

// SignForwarderAttestation populates ff.ForwarderAttestation with an
// Ed25519 signature by the forwarder's identity key over the canonical
// bytes of the ForwardedFrom block, per ENVELOPE.md section 6.6.3.
//
// The forwarder is the user who is performing the forward; their
// identity key is distinct from the original sender's identity key
// already embedded in original_enclosure_plaintext.sender_signature.
func SignForwarderAttestation(ff *ForwardedFrom, suite crypto.Suite, forwarderPrivateKey []byte, forwarderKeyID string) error {
	if ff == nil {
		return errors.New("enclosure: nil forwarded_from")
	}
	if suite == nil {
		return errors.New("enclosure: nil suite")
	}
	if len(forwarderPrivateKey) == 0 {
		return errors.New("enclosure: empty forwarder private key")
	}
	if forwarderKeyID == "" {
		return errors.New("enclosure: empty forwarder key_id")
	}
	ff.ForwarderAttestation = &Signature{
		Algorithm: SignatureAlgorithmEd25519,
		KeyID:     forwarderKeyID,
		Value:     "",
	}
	canonicalBytes, err := canonical.MarshalWithElision(ff, canonical.ForwardedFromElider())
	if err != nil {
		return fmt.Errorf("enclosure: canonical forwarded_from bytes: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxForwarderAttestation, canonicalBytes)
	sig, err := suite.Signer().Sign(forwarderPrivateKey, prefixed)
	if err != nil {
		return fmt.Errorf("enclosure: forwarder attestation sign: %w", err)
	}
	ff.ForwarderAttestation.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyForwarderAttestation confirms ff.ForwarderAttestation was
// produced by forwarderPublicKey over the canonical forwarded_from
// bytes. Does not verify the embedded original_enclosure_plaintext
// sender_signature; pair with VerifyEnclosureSignature for the full
// forwarding verification chain per ENVELOPE.md section 6.6.4.
func VerifyForwarderAttestation(ff *ForwardedFrom, suite crypto.Suite, forwarderPublicKey []byte) error {
	if ff == nil {
		return errors.New("enclosure: nil forwarded_from")
	}
	if suite == nil {
		return errors.New("enclosure: nil suite")
	}
	if ff.ForwarderAttestation == nil {
		return errors.New("enclosure: missing forwarder_attestation")
	}
	if ff.ForwarderAttestation.Algorithm != SignatureAlgorithmEd25519 {
		return fmt.Errorf("enclosure: unsupported forwarder_attestation algorithm %q", ff.ForwarderAttestation.Algorithm)
	}
	claimedSig, err := base64.StdEncoding.DecodeString(ff.ForwarderAttestation.Value)
	if err != nil {
		return fmt.Errorf("enclosure: forwarder_attestation value base64: %w", err)
	}
	canonicalBytes, err := canonical.MarshalWithElision(ff, canonical.ForwardedFromElider())
	if err != nil {
		return fmt.Errorf("enclosure: canonical forwarded_from bytes: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxForwarderAttestation, canonicalBytes)
	if err := suite.Signer().Verify(forwarderPublicKey, prefixed, claimedSig); err != nil {
		return fmt.Errorf("enclosure: forwarder_attestation verify: %w", err)
	}
	return nil
}
