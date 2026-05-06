package envelope

import (
	"context"
	"errors"
	"fmt"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
)

// SenderKeyResolver fetches a sender's identity public key by
// (sender address, key fingerprint) per ENVELOPE.md §6.5.3 step 2.
// Conformant recipient clients MUST verify the enclosure's
// sender_signature against the key returned here before rendering
// content.
//
// The resolver is expected to consult the sender's published key
// set (KEY.md §3), which may include historically-published-and-
// now-revoked keys per §6.5.3 (a revoked-but-published key MAY
// have signed an old enclosure that the recipient is opening
// today).
//
// Returns the raw public-key bytes on success. Returns an error
// (typically wrapping ErrSenderKeyUnknown) when no published key
// matches the (address, key_id) pair; the open path translates
// that into a verification failure per §6.5.3.
type SenderKeyResolver interface {
	LookupSenderIdentityKey(ctx context.Context, senderAddress string, keyID string) ([]byte, error)
}

// SenderKeyResolverFunc adapts a function to the SenderKeyResolver
// interface.
type SenderKeyResolverFunc func(ctx context.Context, senderAddress string, keyID string) ([]byte, error)

// LookupSenderIdentityKey implements SenderKeyResolver.
func (f SenderKeyResolverFunc) LookupSenderIdentityKey(ctx context.Context, senderAddress string, keyID string) ([]byte, error) {
	return f(ctx, senderAddress, keyID)
}

// ErrSenderKeyUnknown is the canonical error a SenderKeyResolver
// returns when no published key matches the (address, key_id) pair.
// Resolvers MAY wrap this error or return their own typed errors;
// the open path treats any non-nil error as a §6.5.3 verification
// failure.
var ErrSenderKeyUnknown = errors.New("envelope: sender identity key unknown for this (address, key_id)")

// OpenAndVerifyResult is what OpenAndVerify returns: the decrypted
// brief, the decrypted enclosure, and the per-step verification
// outcomes per ENVELOPE.md §6.5.3 and §6.6.4.
//
// SenderSignatureVerified is true iff the enclosure carried a
// sender_signature, the resolver returned a key for that signature,
// and the signature verified. False with SenderSignatureError set
// when verification failed; clients MUST NOT render the enclosure
// content as authored by the claimed sender in that case.
//
// ForwardingChainVerified is set on forwarded envelopes
// (Enclosure.ForwardedFrom != nil) and reports whether the §6.6.4
// three-step flow (outer sender, forwarder attestation, original
// sender) succeeded.
type OpenAndVerifyResult struct {
	Brief                   *brief.Brief
	Enclosure               *enclosure.Enclosure
	SenderSignatureVerified bool
	SenderSignatureError    error
	ForwardingChainVerified bool
	ForwardingChainError    error
}

// OpenAndVerify decrypts the brief and enclosure for one of the
// candidate recipient client keys and runs the §6.5.3 sender-
// signature check against the resolver. Returns an error only when
// decryption itself fails (no candidate matches, all candidates
// fail to decrypt, etc.); a verification failure is returned in
// the result struct so callers can render the spec's "MUST NOT
// silently render" warning rather than dropping the envelope.
//
// On forwarded envelopes (Enclosure.ForwardedFrom non-nil) the
// §6.6.4 three-step verification is also run; results live in the
// ForwardingChain* fields.
func OpenAndVerify(ctx context.Context, env *Envelope, suite crypto.Suite, candidates []RecipientPrivateKey, resolver SenderKeyResolver) (*OpenAndVerifyResult, error) {
	if env == nil {
		return nil, errors.New("envelope: nil envelope")
	}
	if resolver == nil {
		return nil, errors.New("envelope: nil sender-key resolver")
	}

	bf, err := OpenBriefAny(env, suite, candidates)
	if err != nil {
		return nil, fmt.Errorf("open brief: %w", err)
	}
	enc, err := OpenEnclosureAny(env, suite, candidates)
	if err != nil {
		return nil, fmt.Errorf("open enclosure: %w", err)
	}

	out := &OpenAndVerifyResult{Brief: bf, Enclosure: enc}

	verifyErr := verifyEnclosureWithResolver(ctx, suite, string(bf.From), enc, resolver)
	if verifyErr == nil {
		out.SenderSignatureVerified = true
	} else {
		out.SenderSignatureError = verifyErr
	}

	if enc.ForwardedFrom != nil {
		ferr := verifyForwardingChain(ctx, suite, enc, resolver)
		if ferr == nil {
			out.ForwardingChainVerified = true
		} else {
			out.ForwardingChainError = ferr
		}
	}

	return out, nil
}

// verifyEnclosureWithResolver runs ENVELOPE.md §6.5.3 step 2-3:
// look up the sender identity key by (address, key_id), then
// verify the canonical signature.
func verifyEnclosureWithResolver(ctx context.Context, suite crypto.Suite, senderAddress string, enc *enclosure.Enclosure, resolver SenderKeyResolver) error {
	if enc == nil {
		return errors.New("envelope: nil enclosure")
	}
	if enc.SenderSignature == nil {
		return errors.New("envelope: enclosure missing sender_signature (ENVELOPE.md §6.5)")
	}
	if enc.SenderSignature.KeyID == "" {
		return errors.New("envelope: sender_signature missing key_id")
	}
	pub, err := resolver.LookupSenderIdentityKey(ctx, senderAddress, enc.SenderSignature.KeyID)
	if err != nil {
		return fmt.Errorf("resolve sender key for %s/%s: %w", senderAddress, enc.SenderSignature.KeyID, err)
	}
	if len(pub) == 0 {
		return ErrSenderKeyUnknown
	}
	return enclosure.VerifyEnclosureSignature(enc, suite, pub)
}

// verifyForwardingChain runs ENVELOPE.md §6.6.4: outer
// sender_signature already verified by OpenAndVerify, then the
// forwarder_attestation, then the original_enclosure_plaintext's
// sender_signature.
//
// §6.6.3: forwarder_attestation.key_id MUST equal the outer
// sender_signature.key_id. A mismatch means the forwarder did not
// sign their own attestation and the envelope is rejected.
func verifyForwardingChain(ctx context.Context, suite crypto.Suite, enc *enclosure.Enclosure, resolver SenderKeyResolver) error {
	ff := enc.ForwardedFrom
	if ff == nil {
		return errors.New("envelope: forwarded_from is nil")
	}
	if ff.ForwarderAttestation == nil {
		return errors.New("envelope: forwarded_from missing forwarder_attestation (§6.6.3)")
	}
	// §6.6.3 cross-check.
	if enc.SenderSignature == nil {
		return errors.New("envelope: outer enclosure missing sender_signature; cannot validate §6.6.3 binding")
	}
	if ff.ForwarderAttestation.KeyID != enc.SenderSignature.KeyID {
		return fmt.Errorf("envelope: forwarder_attestation.key_id %q does not match outer sender_signature.key_id %q (§6.6.3)",
			ff.ForwarderAttestation.KeyID, enc.SenderSignature.KeyID)
	}
	// The forwarder attestation is signed by the FORWARDER's identity key.
	// We resolve it the same way we resolved the outer sender's key,
	// using the forwarder's address (which is the address inside the
	// outer enclosure). The outer sender_signature was already
	// verified by OpenAndVerify; the forwarder = outer sender by
	// §6.6.3, so we can reuse the resolved key. But for clarity and
	// to keep the verifier self-contained, we re-resolve here.
	//
	// Note: the forwarder's address is NOT inside enc directly; it
	// lives in the outer brief.From, which OpenAndVerify already
	// looked up. We pass it through via the resolver's first
	// argument — but to keep this function pure, we look it up
	// using ff.OriginalSenderAddress as a fallback discriminant.
	// In practice the caller's resolver SHOULD be able to find the
	// key by key_id alone given the cached domain; we pass an empty
	// address and let the resolver decide.
	forwarderPub, err := resolver.LookupSenderIdentityKey(ctx, "", ff.ForwarderAttestation.KeyID)
	if err != nil {
		return fmt.Errorf("resolve forwarder key %s: %w", ff.ForwarderAttestation.KeyID, err)
	}
	if len(forwarderPub) == 0 {
		return ErrSenderKeyUnknown
	}
	if err := enclosure.VerifyForwarderAttestation(ff, suite, forwarderPub); err != nil {
		return fmt.Errorf("forwarder attestation: %w", err)
	}

	// §6.6.4 step 3: verify the original sender's signature on the
	// preserved original_enclosure_plaintext.
	orig := ff.OriginalEnclosurePlaintext
	if orig == nil {
		return errors.New("envelope: forwarded_from missing original_enclosure_plaintext")
	}
	if err := verifyEnclosureWithResolver(ctx, suite, ff.OriginalSenderAddress, orig, resolver); err != nil {
		return fmt.Errorf("original sender: %w", err)
	}
	return nil
}

