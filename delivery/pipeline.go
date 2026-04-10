package delivery

import (
	"context"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/envelope"
	"github.com/semp-dev/semp-go/session"
)

// Pipeline runs the fixed delivery pipeline defined in DELIVERY.md §2:
//
//  1. Verify seal.signature                       → seal_invalid
//  2. Check postmark.expires                      → envelope_expired
//  3. Check postmark.session_id                   → handshake_invalid / no_session
//  4. Verify seal.session_mac                     → session_mac_invalid
//  5. Check domain / server policy                → rejected or silent
//  6. Decrypt K_brief from seal.brief_recipients
//  7. Decrypt envelope.brief
//  8. Check user policy (block list)              → rejected or silent
//  9. Deliver to client                           → delivered
//
// Each step is a separate function so that operators can plug in alternate
// policy checks at the same hook points without rewriting the pipeline.
type Pipeline struct {
	Sessions  session.ExpiryLog
	BlockList BlockListLookup
	// SealVerifier verifies steps 1 and 4 against the appropriate keys.
	// In production this is wired to seal.Verifier; the skeleton leaves
	// the field type as an interface so the package can build standalone.
	SealVerifier any
}

// BlockListLookup is the minimal lookup interface the pipeline needs to
// enforce user-level blocks at step 8.
type BlockListLookup interface {
	// IsBlocked reports whether the sender (full address) is blocked by
	// the recipient (full address). The acknowledgment type and reason
	// are determined by the matched BlockEntry.
	IsBlocked(ctx context.Context, recipient, sender string) (semp.Acknowledgment, semp.ReasonCode, bool)
}

// Process runs the full pipeline against env on behalf of the recipient.
// Returns the acknowledgment outcome that the receiving server should
// send back to the sending server (DELIVERY.md §1).
//
// TODO(DELIVERY.md §2): implement, calling each step in order and
// short-circuiting on the first failure.
func (p *Pipeline) Process(ctx context.Context, env *envelope.Envelope, recipient string) (semp.Acknowledgment, *envelope.Rejection, error) {
	_, _, _ = ctx, env, recipient
	return semp.AckDelivered, nil, nil
}
