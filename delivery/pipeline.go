package delivery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/session"
)

// PipelineLogger is the minimal logging interface used by the delivery
// pipeline. The standard library *log.Logger satisfies it via Printf.
type PipelineLogger interface {
	Printf(format string, args ...any)
}

// DomainKeyLookup is the minimal lookup interface needed by step 1 of
// DELIVERY.md §2 — verifying seal.signature against the sender domain's
// published key. Returning (nil, nil) means "no key on file"; the
// pipeline treats that as `seal_invalid` rather than failing open.
type DomainKeyLookup interface {
	LookupDomainPublicKey(ctx context.Context, domain string) ([]byte, error)
}

// DomainPolicyFunc is the optional step-5 hook in DELIVERY.md §2. It is
// called with the postmark.from_domain and the routing server hostname
// (when known) so operators can plug in domain- or server-level
// rate-limiting, reputation gates, or static blocklists. Returning
// AckDelivered means "pass"; AckRejected and AckSilent both terminate
// the pipeline at this step. The reason code is surfaced in the
// envelope-wide rejection.
type DomainPolicyFunc func(ctx context.Context, fromDomain, fromServer string) (semp.Acknowledgment, semp.ReasonCode, string)

// LocalAddressFunc is invoked by the pipeline at step 9 to decide
// whether a recipient address belongs to a local user (in which case
// the envelope is stored in the inbox) or a remote one (in which case
// the recipient is reported as recipient_not_found). The pipeline does
// NOT forward to remote peers itself — that responsibility belongs to
// the caller (inboxd's federation Forwarder).
type LocalAddressFunc func(address string) bool

// InboxStore is the minimal write side of the local inbox. The bundled
// *Inbox satisfies this; tests can provide a fake.
type InboxStore interface {
	Store(address string, payload []byte)
}

// EnvMACFunc returns the K_env_mac the pipeline should use right now.
// Plumbed through a function rather than a static []byte so live
// session rekeying takes effect immediately (the inboxd Server hands
// in a closure that reads from session.Session.EnvMAC()).
type EnvMACFunc func() []byte

// Pipeline runs the receive-side delivery pipeline defined in
// DELIVERY.md §2:
//
//  1. Verify seal.signature                  → seal_invalid
//  2. Check postmark.expires                 → envelope_expired
//  3. Check postmark.session_id              → no_session / handshake_invalid
//  4. Verify seal.session_mac                → session_mac_invalid
//  5. Check domain / server policy           → rejected or silent
//  6. Decrypt K_brief from seal.brief_recipients
//  7. Decrypt envelope.brief
//  8. Check user policy (block list)         → rejected or silent
//  9. Deliver to client                      → delivered
//
// Each numbered step is implemented as a private method on Pipeline so
// operators can subclass or wrap individual steps without rewriting
// the orchestration. The exported Process method runs all steps in
// order and short-circuits on the first failure.
//
// Pipeline does NOT generate signatures or session_macs — that is the
// submission path's job (CLIENT.md §1.3, ENVELOPE.md §7.1 step 8). Set
// SkipSignatureCheck and SkipSessionMACCheck to true when running the
// pipeline against a freshly-signed local-client envelope where the
// home server already controls the signing keys.
type Pipeline struct {
	// Suite is the negotiated cryptographic suite for the connection
	// the envelope arrived on. Required.
	Suite crypto.Suite

	// EnvMAC returns K_env_mac for step 4. May be nil when
	// SkipSessionMACCheck is true.
	EnvMAC EnvMACFunc

	// DomainKeys looks up sender-domain public keys for step 1. May be
	// nil when SkipSignatureCheck is true (the local-client submission
	// path does not need to verify a signature it has not yet
	// produced).
	DomainKeys DomainKeyLookup

	// Sessions is consulted at step 3 to detect retired session ids.
	// Optional: nil disables the retired-session check (the
	// presence-of-session_id check still runs).
	Sessions session.ExpiryLog

	// SkipSignatureCheck disables step 1 entirely. Set this when the
	// envelope was just signed by the local home server in client
	// submission mode and there is no foreign signature to verify.
	SkipSignatureCheck bool

	// SkipSessionMACCheck disables step 4 entirely. Same rationale as
	// SkipSignatureCheck — the home server has not yet bound a
	// session MAC at submission time.
	SkipSessionMACCheck bool

	// SkipExpiryCheck disables step 2. Useful for tests that want to
	// process a stale envelope deterministically; production
	// deployments should leave this false.
	SkipExpiryCheck bool

	// SkipSessionIDCheck disables step 3 (presence-of and retired-by
	// the ExpiryLog). Useful in the same testing situations as
	// SkipExpiryCheck.
	SkipSessionIDCheck bool

	// DomainEncFP and DomainEncPriv are the home server's domain
	// encryption keypair, used to unwrap K_brief in step 6/7. Both
	// MUST be populated.
	DomainEncFP   keys.Fingerprint
	DomainEncPriv []byte

	// DomainPolicy is the optional step-5 hook. Nil disables the step
	// (every envelope passes by default).
	DomainPolicy DomainPolicyFunc

	// BlockList is the step-8 lookup. Nil disables the user-level
	// block check.
	BlockList BlockListLookup

	// IsLocal classifies recipient addresses at step 9. Required.
	IsLocal LocalAddressFunc

	// Inbox is where successfully-delivered envelopes are written at
	// step 9. Nil makes step 9 a no-op (recipients still get a
	// `delivered` outcome but nothing is stored — useful in pure
	// policy tests).
	Inbox InboxStore

	// Logger receives one line per pipeline outcome (one line per
	// envelope at the rejection level, plus one per per-recipient
	// decision when verbose). Nil disables logging.
	Logger PipelineLogger

	// Now is a clock hook for tests. Defaults to time.Now.
	Now func() time.Time
}

// Result is the outcome of a single pipeline run.
//
// Two top-level shapes are possible:
//
//   - Envelope-wide rejection: Rejection is non-nil and Results is
//     empty. The pipeline failed at one of steps 1-7 and never reached
//     per-recipient enforcement. The caller should report the
//     Rejection back to the sender.
//
//   - Per-recipient outcomes: Rejection is nil and Results carries one
//     entry per recipient in brief.to + brief.cc. Some rows may be
//     `delivered`, others `rejected`/`silent` due to per-recipient
//     block lists, others `recipient_not_found` for non-local
//     addresses the caller is expected to forward.
//
// Brief is populated whenever step 6/7 succeeded, even if the pipeline
// later short-circuited at step 8 with a per-recipient block, so the
// caller can log the verified sender address for ops visibility.
type Result struct {
	EnvelopeID string
	Brief      *brief.Brief
	Results    []SubmissionResult
	Rejection  *envelope.Rejection
}

// Rejected is a tiny convenience that reports whether the pipeline
// produced an envelope-wide rejection.
func (r *Result) Rejected() bool { return r != nil && r.Rejection != nil }

// Process runs the full pipeline against env on behalf of the local
// home server and returns a Result. A non-nil error is reserved for
// transport-level failures (e.g. re-encoding the envelope for storage)
// — pipeline-level rejections are surfaced through Result.Rejection
// and per-recipient rejections through Result.Results.
func (p *Pipeline) Process(ctx context.Context, env *envelope.Envelope) (*Result, error) {
	if p == nil {
		return nil, errors.New("delivery: nil pipeline")
	}
	if p.Suite == nil {
		return nil, errors.New("delivery: pipeline missing crypto suite")
	}
	if env == nil {
		return nil, errors.New("delivery: nil envelope")
	}
	if p.IsLocal == nil {
		return nil, errors.New("delivery: pipeline missing IsLocal classifier")
	}
	res := &Result{EnvelopeID: env.Postmark.ID}

	// Step 1: verify seal.signature.
	if !p.SkipSignatureCheck {
		if rej := p.verifySignature(ctx, env); rej != nil {
			res.Rejection = rej
			p.logRejection(env, rej)
			return res, nil
		}
	}
	// Step 2: postmark.expires.
	if !p.SkipExpiryCheck {
		if rej := p.checkExpiry(env); rej != nil {
			res.Rejection = rej
			p.logRejection(env, rej)
			return res, nil
		}
	}
	// Step 3: postmark.session_id (presence + retirement).
	if !p.SkipSessionIDCheck {
		if rej := p.checkSessionID(ctx, env); rej != nil {
			res.Rejection = rej
			p.logRejection(env, rej)
			return res, nil
		}
	}
	// Step 4: seal.session_mac.
	if !p.SkipSessionMACCheck {
		if rej := p.verifySessionMAC(env); rej != nil {
			res.Rejection = rej
			p.logRejection(env, rej)
			return res, nil
		}
	}
	// Step 5: domain / server policy.
	if rej := p.checkDomainPolicy(ctx, env); rej != nil {
		res.Rejection = rej
		p.logRejection(env, rej)
		return res, nil
	}
	// Steps 6 + 7: unwrap and decrypt the brief.
	bf, rej := p.openBrief(env)
	if rej != nil {
		res.Rejection = rej
		p.logRejection(env, rej)
		return res, nil
	}
	res.Brief = bf

	// Steps 8 + 9: per-recipient block check + delivery.
	wire, err := envelope.Encode(env)
	if err != nil {
		return nil, fmt.Errorf("delivery: re-encode envelope %s: %w", env.Postmark.ID, err)
	}
	res.Results, err = p.deliverRecipients(ctx, env, bf, wire)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// -----------------------------------------------------------------------------
// Step implementations
// -----------------------------------------------------------------------------

// verifySignature implements DELIVERY.md §2 step 1.
func (p *Pipeline) verifySignature(ctx context.Context, env *envelope.Envelope) *envelope.Rejection {
	if p.DomainKeys == nil {
		return p.reject(env, semp.ReasonSealInvalid,
			"pipeline missing DomainKeys lookup; cannot verify seal.signature")
	}
	pub, err := p.DomainKeys.LookupDomainPublicKey(ctx, env.Postmark.FromDomain)
	if err != nil {
		return p.reject(env, semp.ReasonSealInvalid,
			fmt.Sprintf("lookup domain key for %s: %v", env.Postmark.FromDomain, err))
	}
	if len(pub) == 0 {
		return p.reject(env, semp.ReasonSealInvalid,
			fmt.Sprintf("no domain key on file for %s", env.Postmark.FromDomain))
	}
	if err := envelope.VerifySignature(env, p.Suite, pub); err != nil {
		return p.reject(env, semp.ReasonSealInvalid, err.Error())
	}
	return nil
}

// checkExpiry implements DELIVERY.md §2 step 2.
func (p *Pipeline) checkExpiry(env *envelope.Envelope) *envelope.Rejection {
	if env.Postmark.Expires.IsZero() {
		// A missing expiry is structurally invalid — ENVELOPE.md §3.1
		// makes the field required — but the schema validators in
		// envelope.Decode already enforce shape. Treat a zero value
		// here as "no expiry" for forward compatibility.
		return nil
	}
	if !p.now().Before(env.Postmark.Expires) {
		return p.reject(env, semp.ReasonEnvelopeExpired,
			fmt.Sprintf("postmark.expires %s is not in the future", env.Postmark.Expires.UTC().Format(time.RFC3339)))
	}
	return nil
}

// checkSessionID implements DELIVERY.md §2 step 3.
func (p *Pipeline) checkSessionID(ctx context.Context, env *envelope.Envelope) *envelope.Rejection {
	if strings.TrimSpace(env.Postmark.SessionID) == "" {
		return p.reject(env, semp.ReasonNoSession, "postmark.session_id is empty")
	}
	if p.Sessions == nil {
		return nil
	}
	retired, err := p.Sessions.Retired(ctx, env.Postmark.SessionID)
	if err != nil {
		// Lookup failures fail open — log and continue rather than
		// blackhole every envelope on a transient store error.
		p.logf("session expiry lookup error for %s: %v", env.Postmark.SessionID, err)
		return nil
	}
	if retired {
		return p.reject(env, semp.ReasonHandshakeInvalid,
			fmt.Sprintf("session_id %s is retired", env.Postmark.SessionID))
	}
	return nil
}

// verifySessionMAC implements DELIVERY.md §2 step 4.
func (p *Pipeline) verifySessionMAC(env *envelope.Envelope) *envelope.Rejection {
	if p.EnvMAC == nil {
		return p.reject(env, semp.ReasonSessionMACInvalid,
			"pipeline missing EnvMAC source; cannot verify seal.session_mac")
	}
	mac := p.EnvMAC()
	if len(mac) == 0 {
		return p.reject(env, semp.ReasonSessionMACInvalid,
			"empty K_env_mac; cannot verify seal.session_mac")
	}
	if err := envelope.VerifySessionMAC(env, p.Suite, mac); err != nil {
		return p.reject(env, semp.ReasonSessionMACInvalid, err.Error())
	}
	return nil
}

// checkDomainPolicy implements DELIVERY.md §2 step 5.
func (p *Pipeline) checkDomainPolicy(ctx context.Context, env *envelope.Envelope) *envelope.Rejection {
	if p.DomainPolicy == nil {
		return nil
	}
	// We do not currently track per-hop server hostnames in the
	// envelope; the postmark only carries from_domain. The hook is
	// passed an empty server string for forward compatibility — once
	// we add a routed-through-server field to the postmark we can
	// thread it here.
	ack, code, reason := p.DomainPolicy(ctx, env.Postmark.FromDomain, "")
	switch ack {
	case "", semp.AckDelivered:
		return nil
	case semp.AckRejected:
		if code == "" {
			code = semp.ReasonPolicyViolation
		}
		if reason == "" {
			reason = "domain policy rejected envelope"
		}
		return p.reject(env, code, reason)
	case semp.AckSilent:
		// Silent mode at the domain level: surface as a rejection
		// internally but with the silent acknowledgment so the caller
		// can suppress the response. We use a sentinel reason code
		// (policy_violation) and the reason text "silent" so callers
		// matching on Result.Rejection can branch on the
		// acknowledgment via the reason text. Future work: add a
		// dedicated AckSilent envelope-level signal.
		if code == "" {
			code = semp.ReasonPolicyViolation
		}
		if reason == "" {
			reason = "domain policy: silent"
		}
		return p.reject(env, code, reason)
	default:
		return nil
	}
}

// openBrief implements DELIVERY.md §2 steps 6 and 7.
func (p *Pipeline) openBrief(env *envelope.Envelope) (*brief.Brief, *envelope.Rejection) {
	if len(p.DomainEncPriv) == 0 || p.DomainEncFP == "" {
		return nil, p.reject(env, semp.ReasonSealInvalid,
			"pipeline missing domain encryption key; cannot unwrap brief")
	}
	bf, err := envelope.OpenBrief(env, p.Suite, p.DomainEncFP, p.DomainEncPriv)
	if err != nil {
		return nil, p.reject(env, semp.ReasonSealInvalid,
			fmt.Sprintf("server cannot unwrap brief: %v", err))
	}
	return bf, nil
}

// deliverRecipients implements DELIVERY.md §2 steps 8 and 9.
func (p *Pipeline) deliverRecipients(ctx context.Context, env *envelope.Envelope, bf *brief.Brief, wire []byte) ([]SubmissionResult, error) {
	recipients := append([]brief.Address{}, bf.To...)
	recipients = append(recipients, bf.CC...)
	results := make([]SubmissionResult, 0, len(recipients))

	senderAddress := string(bf.From)
	senderDomain := env.Postmark.FromDomain
	// Same forward-compatibility note as checkDomainPolicy: per-hop
	// server hostname is not yet plumbed through the envelope.
	const senderServer = ""
	isGroup := bf.GroupID != ""

	for _, addr := range recipients {
		address := string(addr)
		if !p.IsLocal(address) {
			results = append(results, SubmissionResult{
				Recipient: address,
				Status:    semp.StatusRecipientNotFound,
				Reason:    "recipient is not local to this pipeline",
			})
			continue
		}
		// Step 8: per-recipient block-list lookup.
		if p.BlockList != nil {
			list, err := p.BlockList.Lookup(ctx, address)
			if err != nil {
				return nil, fmt.Errorf("delivery: lookup block list for %s: %w", address, err)
			}
			if entry := list.Match(senderAddress, senderDomain, senderServer, isGroup); entry != nil {
				switch entry.Acknowledgment {
				case semp.AckSilent:
					results = append(results, SubmissionResult{
						Recipient: address,
						Status:    semp.StatusSilent,
					})
					p.logf("[delivery] silent block: envelope=%s recipient=%s sender=%s entry=%s",
						env.Postmark.ID, address, senderAddress, entry.ID)
					continue
				case semp.AckRejected, "":
					results = append(results, SubmissionResult{
						Recipient:  address,
						Status:     semp.StatusRejected,
						ReasonCode: semp.ReasonBlocked,
						Reason:     "blocked by recipient policy",
					})
					p.logf("[delivery] blocked: envelope=%s recipient=%s sender=%s entry=%s",
						env.Postmark.ID, address, senderAddress, entry.ID)
					continue
				}
			}
		}
		// Step 9: deliver locally.
		if p.Inbox != nil {
			p.Inbox.Store(address, wire)
		}
		results = append(results, SubmissionResult{
			Recipient: address,
			Status:    semp.StatusDelivered,
		})
		p.logf("[delivery] delivered: envelope=%s recipient=%s sender=%s",
			env.Postmark.ID, address, senderAddress)
	}
	return results, nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (p *Pipeline) reject(env *envelope.Envelope, code semp.ReasonCode, reason string) *envelope.Rejection {
	return &envelope.Rejection{
		EnvelopeID: env.Postmark.ID,
		Code:       code,
		Reason:     reason,
		Timestamp:  p.now(),
	}
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now().UTC()
}

func (p *Pipeline) logf(format string, args ...any) {
	if p.Logger == nil {
		return
	}
	p.Logger.Printf(format, args...)
}

func (p *Pipeline) logRejection(env *envelope.Envelope, rej *envelope.Rejection) {
	if rej == nil {
		return
	}
	p.logf("[delivery] rejected: envelope=%s reason_code=%s reason=%q from_domain=%s",
		env.Postmark.ID, rej.Code, rej.Reason, env.Postmark.FromDomain)
}
