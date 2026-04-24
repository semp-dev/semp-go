// Package inboxd is the post-handshake server-side message loop used by
// the cmd/semp-server demo binary. It serves two operations:
//
//   - Envelope submission: client uploads a SEMP envelope; server signs
//     it (envelope.Sign), unwraps the brief to learn the recipient list,
//     stores the envelope in the per-recipient inbox, and replies with a
//     SEMP_SUBMISSION response.
//
//   - Envelope fetch: client sends a SEMP_FETCH request and receives every
//     waiting envelope from its inbox. SEMP_FETCH is a demo-only extension
//     (HANDSHAKE.md §4.6 leaves the wakeup mechanism out of scope).
//
// The loop runs until the peer closes the connection or the context is
// cancelled. Errors that aren't part of normal client disconnect are
// logged via the supplied Logger.
//
// inboxd is intentionally cross-domain unaware. Envelopes addressed to
// recipients outside Server.LocalDomain are returned with status
// recipient_not_found. The cross-domain federation routing path is the
// next milestone.
package inboxd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/session"
)

var (
	base64Std    = base64.StdEncoding
	base64RawStd = base64.RawStdEncoding
)

// MessageStream is the minimal interface inboxd needs from a transport.
// transport.Conn satisfies it; tests can substitute an in-memory channel
// pair without pulling in the transport package.
type MessageStream interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
}

// Logger is the minimal logging interface used by Serve. The standard
// library *log.Logger satisfies it via its Printf method.
type Logger interface {
	Printf(format string, args ...any)
}

// Mode identifies how an inboxd Server should treat incoming envelopes.
type Mode int

// Mode values.
const (
	// ModeClient — the peer is a local client submitting envelopes on
	// behalf of its owning user. The server fills in seal.signature
	// and seal.session_mac, unwraps the brief, routes locally or via
	// the federation Forwarder, and replies with SubmissionResponse.
	ModeClient Mode = iota

	// ModeFederation — the peer is a remote server forwarding
	// envelopes from its own users. The server does NOT re-sign: the
	// original sender-domain signature is already in place and must be
	// left intact as the provenance proof. The server verifies both
	// seal.signature (against the remote sender's published domain
	// key) and seal.session_mac (against THIS federation session's
	// K_env_mac, which is what the initiator bound it to before
	// forwarding). It unwraps the brief, routes locally, and replies
	// with a SubmissionResponse.
	ModeFederation
)

// Server holds the state needed to serve one connected peer. A fresh
// Server is constructed per accepted connection by the demo binary.
type Server struct {
	// Mode controls whether Serve runs in ModeClient or ModeFederation.
	// Defaults to ModeClient (the zero value).
	Mode Mode

	// Suite is the negotiated cryptographic suite for this session. Same
	// value the handshake used.
	Suite crypto.Suite

	// Store is the keys.Store used for peer lookups (currently only
	// federation mode uses it, to verify the original sender domain's
	// signature on incoming envelopes).
	Store keys.Store

	// Inbox is the shared in-memory queue. Multiple Server instances
	// (one per connection) write into the same Inbox.
	Inbox *delivery.Inbox

	// BlockList is the per-recipient block list lookup applied at
	// step 8 of the delivery pipeline (DELIVERY.md §2). Optional: a
	// nil lookup means "no blocks configured" and all envelopes pass
	// the user-policy step.
	BlockList delivery.BlockListLookup

	// DomainPolicy is the optional step-5 hook on the delivery
	// pipeline (DELIVERY.md §2). It is called with the verified
	// postmark.from_domain so operators can plug in domain-level
	// reputation gates, rate limiting, or static deny lists.
	DomainPolicy delivery.DomainPolicyFunc

	// SessionExpiry, if non-nil, is consulted at pipeline step 3
	// (DELIVERY.md §2 / SESSION.md §5.2) to detect retired session
	// ids. Optional: nil disables the retirement check.
	SessionExpiry session.ExpiryLog

	// Forwarder, if non-nil, is consulted in ModeClient when an envelope
	// is addressed to a recipient outside LocalDomain. A nil Forwarder
	// means cross-domain recipients get recipient_not_found.
	Forwarder *Forwarder

	// LocalDomain is the server's own domain. Recipients on this domain
	// are delivered locally; everyone else is routed via Forwarder.
	LocalDomain string

	// DomainSignFP and DomainSignPriv are the server's long-term
	// signing key, used to sign envelopes during submission (ModeClient).
	DomainSignFP   keys.Fingerprint
	DomainSignPriv []byte

	// DomainEncFP, DomainEncPriv, and DomainEncPub are the server's
	// domain encryption keypair, used to unwrap K_brief from inbound
	// envelopes so the server can read brief.to and brief.from.
	DomainEncFP   keys.Fingerprint
	DomainEncPriv []byte
	DomainEncPub  []byte

	// Identity is the authenticated peer identity established by the
	// preceding handshake. In ModeClient this is the client's user
	// address; in ModeFederation it is the peer server's domain.
	Identity string

	// DeviceKeyID is the fingerprint of the long-term device key the
	// client used to sign the handshake's identity proof. In
	// ModeClient the dispatch loop consults
	// Store.LookupDeviceCertificate(DeviceKeyID) on every envelope
	// submission; if a certificate is present its scope is enforced
	// per CLIENT.md §2.4. If no certificate exists, the device is
	// treated as full-access (the common case for a primary device).
	// Unused in ModeFederation.
	DeviceKeyID keys.Fingerprint

	// Session, if non-nil, is the live *session.Session backing this
	// connection. The dispatch loop uses it to run in-session rekey
	// exchanges (SEMP_REKEY) and always reads K_env_mac from the
	// session's current state, so that rekey events transparently
	// rotate the key under which envelopes are signed and verified.
	//
	// If Session is nil, the loop falls back to the static EnvMAC
	// field below, which is the legacy code path. Tests and the
	// reference binaries always set Session.
	Session *session.Session

	// EnvMAC is the static K_env_mac used when Session is nil. When
	// Session is non-nil, this field is IGNORED — the live session
	// value (session.EnvMAC()) is used instead so rekey events take
	// effect immediately.
	EnvMAC []byte

	// Logger receives operational notes (one line per accepted/rejected
	// envelope, one line per fetch). May be nil to disable logging.
	Logger Logger
}

// envMAC returns the K_env_mac this loop should use for signing or
// verifying envelopes right now. When a live Session is set it reads
// from the session (so rekey events are picked up immediately);
// otherwise it falls back to the static EnvMAC field.
func (s *Server) envMAC() []byte {
	if s.Session != nil {
		return s.Session.EnvMAC()
	}
	return s.EnvMAC
}

// pipelineFor constructs a fresh delivery.Pipeline configured for the
// given mode. ModeClient skips the signature and session_mac checks
// because the home server has just produced both during submission;
// ModeFederation runs every step against the foreign envelope.
//
// Both modes share the same brief unwrap, block-list and inbox-store
// configuration so a refactor that changes the policy or storage
// surface lands in one place rather than two duplicated handlers.
func (s *Server) pipelineFor(mode Mode) *delivery.Pipeline {
	p := &delivery.Pipeline{
		Suite:         s.Suite,
		EnvMAC:        s.envMAC,
		Sessions:      s.SessionExpiry,
		DomainEncFP:   s.DomainEncFP,
		DomainEncPriv: s.DomainEncPriv,
		DomainEncPub:  s.DomainEncPub,
		DomainPolicy:  s.DomainPolicy,
		BlockList:     s.BlockList,
		IsLocal:       s.isLocal,
		Inbox:         s.Inbox,
		Logger:        s.Logger,
	}
	switch mode {
	case ModeClient:
		// The home server signs the envelope itself in this path, so
		// there is no foreign signature or session_mac to verify; both
		// are present after envelope.Sign but verifying them would
		// just confirm what we just produced.
		p.SkipSignatureCheck = true
		p.SkipSessionMACCheck = true
	case ModeFederation:
		// Wire DomainKeys to the configured keys.Store. The pipeline
		// uses the lookup at step 1 to fetch the original sender
		// domain's published signing key.
		if s.Store != nil {
			p.DomainKeys = &storeDomainKeyLookup{store: s.Store}
		}
	}
	return p
}

// storeDomainKeyLookup adapts a keys.Store to delivery.DomainKeyLookup.
// The pipeline expects raw public-key bytes; the store records carry
// base64-encoded strings, so this thin shim handles the decode and
// returns ENOKEY-equivalent (nil, nil) when the domain has no record on
// file.
type storeDomainKeyLookup struct {
	store keys.Store
}

func (s *storeDomainKeyLookup) LookupDomainPublicKey(ctx context.Context, domain string) ([]byte, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	rec, err := s.store.LookupDomainKey(ctx, domain)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return decodeBase64(rec.PublicKey)
}

// Serve runs the post-handshake message loop until the peer closes the
// connection or ctx is cancelled. Returns nil for clean shutdown,
// io.EOF if the peer closed without an error, or the underlying error
// otherwise.
func (s *Server) Serve(ctx context.Context, stream MessageStream) error {
	if s == nil || s.Suite == nil || s.Inbox == nil {
		return errors.New("inboxd: incomplete Server configuration")
	}
	for {
		raw, err := stream.Recv(ctx)
		if err != nil {
			if isClientClose(err) {
				return io.EOF
			}
			return fmt.Errorf("inboxd: recv: %w", err)
		}
		msgType, err := peekType(raw)
		if err != nil {
			s.logf("[%s] dropping malformed message: %v", s.Identity, err)
			continue
		}
		switch msgType {
		case envelope.MessageType:
			if err := s.handleSubmission(ctx, stream, raw); err != nil {
				s.logf("[%s] submission error: %v", s.Identity, err)
				// Don't tear down the loop on per-envelope errors;
				// the response we already sent (or attempted to send)
				// has the per-recipient detail.
			}
		case delivery.FetchType:
			if err := s.handleFetch(ctx, stream, raw); err != nil {
				s.logf("[%s] fetch error: %v", s.Identity, err)
				return err
			}
		case keys.RequestType:
			if err := s.handleKeys(ctx, stream, raw); err != nil {
				s.logf("[%s] keys error: %v", s.Identity, err)
				// SEMP_KEYS failures are per-address; the response
				// already carries the per-address error status.
			}
		case session.MessageType:
			if err := s.handleRekey(ctx, stream, raw); err != nil {
				s.logf("[%s] rekey error: %v", s.Identity, err)
				// Rekey errors are handled by the handler by
				// writing a rekey_rejected; only transport failures
				// propagate here.
			}
		default:
			s.logf("[%s] unsupported message type %q", s.Identity, msgType)
		}
	}
}

// handleSubmission processes one envelope upload. The behavior differs
// between ModeClient (sender-side: sign, then route) and ModeFederation
// (receiver-side: verify, then route locally only).
func (s *Server) handleSubmission(ctx context.Context, stream MessageStream, raw []byte) error {
	env, err := envelope.Decode(raw)
	if err != nil {
		resp := delivery.NewSubmissionResponse("malformed", []delivery.SubmissionResult{{
			Recipient:  s.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:     err.Error(),
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("decode envelope: %w", err)
	}

	switch s.Mode {
	case ModeClient:
		return s.handleClientSubmission(ctx, stream, env)
	case ModeFederation:
		return s.handleFederationSubmission(ctx, stream, env)
	default:
		return fmt.Errorf("inboxd: unknown mode %d", s.Mode)
	}
}

// handleClientSubmission is the ModeClient path. The envelope arrives
// unsigned from the client; the server signs it, runs the delivery
// pipeline (DELIVERY.md §2 steps 5–9, with the foreign-signature and
// session_mac checks skipped because we just produced both), and then
// post-processes any non-local recipients into forwarder calls.
func (s *Server) handleClientSubmission(ctx context.Context, stream MessageStream, env *envelope.Envelope) error {
	// The client transmits the envelope WITHOUT seal.signature or
	// seal.session_mac populated. The home server fills both in per
	// CLIENT.md §1.3 / ENVELOPE.md §7.1 step 8.
	if err := envelope.Sign(env, s.Suite, s.DomainSignPriv, s.envMAC()); err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  s.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:     err.Error(),
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("sign envelope: %w", err)
	}

	// We need the brief here too to drive scope enforcement before we
	// hand the envelope to the pipeline. The pipeline will unwrap the
	// brief a second time during step 6/7 — that double-unwrap is the
	// price of running the scope check (a sender-side concern) at
	// submission time before the envelope reaches the receiver
	// pipeline (a receiver-side concern).
	bf, err := envelope.OpenBrief(env, s.Suite, s.DomainEncFP, s.DomainEncPriv, s.DomainEncPub)
	if err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  s.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:     fmt.Sprintf("server cannot unwrap brief: %v", err),
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("open brief: %w", err)
	}

	allRecipients := append([]brief.Address{}, bf.To...)
	allRecipients = append(allRecipients, bf.CC...)

	// Scope enforcement: if the authenticated device has a
	// certificate, check every recipient against scope.send per
	// CLIENT.md §2.4. This is a sender-side control and runs BEFORE
	// the receive pipeline so a delegated device cannot use the
	// pipeline's policy hooks to leak information about recipients
	// outside its scope.
	scopeResults, scopeAllRejected, err := s.enforceSendScope(ctx, env.Postmark.ID, allRecipients)
	if err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  s.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonPolicyForbidden,
			Reason:     err.Error(),
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("enforce scope: %w", err)
	}
	if scopeAllRejected {
		// At least one recipient was blocked AND none passed the
		// scope check: surface the rejections without delivering
		// anything.
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, scopeResults)
		return sendJSON(ctx, stream, resp)
	}

	// Run the delivery pipeline. ModeClient skips the signature and
	// session_mac verification steps (we just produced both).
	pipe := s.pipelineFor(ModeClient)
	pipeResult, err := pipe.Process(ctx, env)
	if err != nil {
		return fmt.Errorf("client pipeline: %w", err)
	}
	if pipeResult.Rejected() {
		rej := pipeResult.Rejection
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  s.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: rej.Code,
			Reason:     rej.Reason,
		}})
		return sendJSON(ctx, stream, resp)
	}

	// Merge scope-rejection rows back in: scopeResults overrides
	// whatever the pipeline produced for the same recipient because
	// scope checks are sender-side and authoritative. The pipeline
	// would have blocked the same recipient as `recipient_not_found`
	// for non-local destinations, but we want the more informative
	// `scope_exceeded` rejection to surface to the client instead.
	blocked := make(map[string]delivery.SubmissionResult, len(scopeResults))
	for _, r := range scopeResults {
		if r.Status == semp.StatusRejected {
			blocked[r.Recipient] = r
		}
	}

	// Walk the pipeline results and replace any non-local
	// `recipient_not_found` rows with the actual forwarder outcome.
	// Local rows are kept as-is — the pipeline already wrote them to
	// the inbox at step 9.
	wire, err := envelope.Encode(env)
	if err != nil {
		return fmt.Errorf("re-encode envelope: %w", err)
	}
	results := make([]delivery.SubmissionResult, 0, len(pipeResult.Results))
	for _, row := range pipeResult.Results {
		if r, ok := blocked[row.Recipient]; ok {
			results = append(results, r)
			continue
		}
		if row.Status != semp.StatusRecipientNotFound {
			// Local outcome (delivered, rejected, silent) — keep it.
			if row.Status == semp.StatusDelivered {
				s.logf("[%s] delivered envelope %s → %s (local)",
					s.Identity, env.Postmark.ID, row.Recipient)
			}
			results = append(results, row)
			continue
		}
		// Non-local recipient: try the forwarder.
		address := row.Recipient
		if s.Forwarder == nil {
			results = append(results, delivery.SubmissionResult{
				Recipient: address,
				Status:    semp.StatusRecipientNotFound,
				Reason:    "cross-domain forwarding is not enabled on this server",
			})
			s.logf("[%s] no forwarder: %s → recipient_not_found", s.Identity, address)
			continue
		}
		peerDomain := domainOf(address)
		// Clone the envelope per peer so each forward gets its own
		// session_mac re-bind without stomping on the other recipients.
		forwardEnv, err := envelope.Decode(wire)
		if err != nil {
			results = append(results, delivery.SubmissionResult{
				Recipient:  address,
				Status:     semp.StatusRejected,
				ReasonCode: semp.ReasonSealInvalid,
				Reason:     "forwarding failed",
			})
			continue
		}
		peerResp, err := s.Forwarder.Forward(ctx, peerDomain, forwardEnv)
		if err != nil {
			results = append(results, delivery.SubmissionResult{
				Recipient: address,
				Status:    semp.StatusRejected,
				Reason:    "forwarding to remote domain failed",
			})
			s.logf("[%s] forward %s → %s failed: %v", s.Identity, env.Postmark.ID, address, err)
			continue
		}
		// The peer's response carries per-recipient results of its
		// own. Surface each one back to the client verbatim.
		for _, peerResult := range peerResp.Results {
			results = append(results, peerResult)
			s.logf("[%s] forwarded envelope %s → %s: status=%s",
				s.Identity, env.Postmark.ID, peerResult.Recipient, peerResult.Status)
		}
	}

	resp := delivery.NewSubmissionResponse(env.Postmark.ID, results)
	return sendJSON(ctx, stream, resp)
}

// handleFederationSubmission is the ModeFederation path. The envelope
// arrives ALREADY signed by the original sender domain and ALREADY
// session-MACed under this federation session's K_env_mac (the peer
// rebound it before forwarding). The pipeline runs every step of
// DELIVERY.md §2: it verifies both proofs (signature against the
// original sender domain's published key, session_mac against OUR
// K_env_mac), unwraps the brief, applies the user-level block list,
// and stores envelopes for local recipients. We MUST NOT re-sign —
// the domain signature is provenance and any change would break it.
//
// Federation mode does not multi-hop. Recipients that somehow show up
// in an inbound federation envelope addressed to a different domain
// are reported as recipient_not_found; in practice the sending peer
// would have filtered them out before forwarding.
func (s *Server) handleFederationSubmission(ctx context.Context, stream MessageStream, env *envelope.Envelope) error {
	pipe := s.pipelineFor(ModeFederation)
	pipeResult, err := pipe.Process(ctx, env)
	if err != nil {
		return fmt.Errorf("federation pipeline: %w", err)
	}
	if pipeResult.Rejected() {
		rej := pipeResult.Rejection
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  s.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: rej.Code,
			Reason:     rej.Reason,
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("federation pipeline rejected envelope: %s", rej.Code)
	}
	// Override the pipeline's generic "recipient is not local" reason
	// text with the federation-specific "endpoint does not multi-hop"
	// for clarity in cross-domain logs.
	for i := range pipeResult.Results {
		if pipeResult.Results[i].Status == semp.StatusRecipientNotFound {
			pipeResult.Results[i].Reason = "federation endpoint does not multi-hop"
		} else if pipeResult.Results[i].Status == semp.StatusDelivered {
			s.logf("[%s] federated delivery %s → %s",
				s.Identity, env.Postmark.ID, pipeResult.Results[i].Recipient)
		}
	}
	resp := delivery.NewSubmissionResponse(env.Postmark.ID, pipeResult.Results)
	return sendJSON(ctx, stream, resp)
}

// handleKeys fulfills a SEMP_KEYS request from the peer. Local addresses
// are served directly from the server's own store; addresses on a peer
// domain known to the Forwarder are fetched cross-domain via the
// federation session. Unknown domains return status="not_found".
//
// Reference: CLIENT.md §5.4, §5.4.6.
func (s *Server) handleKeys(ctx context.Context, stream MessageStream, raw []byte) error {
	var req keys.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("parse SEMP_KEYS request: %w", err)
	}
	if req.Type != keys.RequestType || req.Step != keys.RequestStepRequest {
		return fmt.Errorf("unexpected SEMP_KEYS type/step: %s/%s", req.Type, req.Step)
	}

	// Group requested addresses by domain so we can answer local
	// addresses directly and batch remote lookups per peer.
	byDomain := make(map[string][]string, 4)
	ordered := make([]string, 0, len(req.Addresses))
	for _, addr := range req.Addresses {
		d := domainOf(addr)
		if _, seen := byDomain[d]; !seen {
			ordered = append(ordered, d)
		}
		byDomain[d] = append(byDomain[d], addr)
	}

	results := make([]keys.ResponseResult, 0, len(req.Addresses))
	// Keep the results in the same order the client requested them.
	for _, addr := range req.Addresses {
		d := domainOf(addr)
		if d == s.LocalDomain {
			local := s.lookupLocalKeys(ctx, addr, req.IncludeDomainKeys)
			if local.Status == keys.StatusFound {
				if err := s.signLocalResult(&local); err != nil {
					local.Status = keys.StatusError
					local.ErrorReason = err.Error()
				}
			}
			results = append(results, local)
			continue
		}
		// Remote domain. Try the Forwarder.
		if s.Forwarder == nil {
			results = append(results, keys.ResponseResult{
				Address: addr,
				Status:  keys.StatusNotFound,
				Domain:  d,
			})
			continue
		}
		// If we don't have a peer config for this domain, treat it
		// the same as "no SEMP support" — StatusNotFound per
		// CLIENT.md §5.4.6. A production server with a real
		// discovery layer might return StatusError with a retry
		// hint, but for the demo this is the simplest truthful
		// answer.
		if _, ok := s.Forwarder.Peers.Lookup(d); !ok {
			results = append(results, keys.ResponseResult{
				Address: addr,
				Status:  keys.StatusNotFound,
				Domain:  d,
			})
			continue
		}
		// Fetch once per remote domain and reuse the response for
		// every address on that domain.
		peerResp, err := s.cachedRemoteFetch(ctx, d, byDomain[d])
		if err != nil {
			results = append(results, keys.ResponseResult{
				Address:     addr,
				Status:      keys.StatusError,
				Domain:      d,
				ErrorReason: err.Error(),
			})
			continue
		}
		// Copy the matching entry out of peerResp.Results.
		found := false
		for _, r := range peerResp.Results {
			if r.Address == addr {
				results = append(results, r)
				found = true
				break
			}
		}
		if !found {
			results = append(results, keys.ResponseResult{
				Address: addr,
				Status:  keys.StatusNotFound,
				Domain:  d,
			})
		}
	}
	_ = ordered // silence linter — kept in case we want ordered iteration later

	resp := keys.NewResponse(req.ID, results)
	return sendJSON(ctx, stream, resp)
}

// lookupLocalKeys serves one address from the server's own keys.Store.
// It returns status="not_found" if the address has no published keys.
func (s *Server) lookupLocalKeys(ctx context.Context, address string, includeDomain bool) keys.ResponseResult {
	domain := domainOf(address)
	result := keys.ResponseResult{
		Address: address,
		Domain:  domain,
		Status:  keys.StatusNotFound,
	}
	if s.Store == nil {
		return result
	}
	userKeys, err := s.Store.LookupUserKeys(ctx, address)
	if err != nil {
		result.Status = keys.StatusError
		result.ErrorReason = err.Error()
		return result
	}
	if len(userKeys) == 0 {
		return result
	}
	result.UserKeys = userKeys
	result.Status = keys.StatusFound
	if includeDomain {
		if domRec, err := s.Store.LookupDomainKey(ctx, domain); err == nil && domRec != nil {
			result.DomainKey = domRec
		}
		if domEncLookup, ok := s.Store.(domainEncKeyLookup); ok {
			if encRec := domEncLookup.LookupDomainEncryptionKey(domain); encRec != nil {
				result.DomainEncKey = encRec
			}
		}
	}
	return result
}

// domainEncKeyLookup is the optional interface an inboxd Store may
// implement to expose the domain encryption key alongside the signing
// key. keys/memstore.Store satisfies it; other implementations can
// opt in as they grow support.
type domainEncKeyLookup interface {
	LookupDomainEncryptionKey(domain string) *keys.Record
}

// enforceSendScope applies the CLIENT.md §2.4 scope check to the
// given recipient list using the device certificate attached to
// s.DeviceKeyID in the local store.
//
// Returns:
//   - rejections: one SubmissionResult per recipient that was
//     blocked by the scope. Empty when no cert exists, when the
//     cert's scope.send.mode is "all", or when all recipients
//     passed the scope check.
//   - allBlocked: true when EVERY recipient was blocked (scope
//     mode=none, or every recipient is outside a restricted scope).
//     The caller uses this to short-circuit delivery for submissions
//     where nothing would make it through.
//   - err: a fatal error that blocks the entire submission (e.g. a
//     certificate whose chain does not verify). This is distinct
//     from per-recipient rejections: a broken cert kills the
//     submission entirely, per CLIENT.md §2.3 (the server MUST
//     reject a registration without a valid authorization proof).
func (s *Server) enforceSendScope(ctx context.Context, envelopeID string, recipients []brief.Address) (rejections []delivery.SubmissionResult, allBlocked bool, err error) {
	if s.DeviceKeyID == "" || s.Store == nil {
		return nil, false, nil
	}
	cert, err := s.Store.LookupDeviceCertificate(ctx, s.DeviceKeyID)
	if err != nil {
		return nil, false, fmt.Errorf("lookup device certificate: %w", err)
	}
	if cert == nil {
		// No certificate means this is a primary (full-access)
		// device: scope checks do not apply.
		return nil, false, nil
	}
	// Verify the chain: the issuing device key must be a registered
	// identity key for the cert's UserID, and the signature must
	// check out. A broken chain is fatal.
	if err := cert.VerifyChain(ctx, s.Suite, s.Store); err != nil {
		return nil, false, fmt.Errorf("verify device certificate chain: %w", err)
	}
	// Cross-check: the certificate MUST identify THIS device and
	// this user. A mismatch means the store returned someone else's
	// cert, which is a configuration bug; fail closed.
	if cert.DeviceKeyID != s.DeviceKeyID {
		return nil, false, fmt.Errorf("device certificate mismatch: cert for %s, session for %s",
			cert.DeviceKeyID, s.DeviceKeyID)
	}
	if cert.UserID != s.Identity {
		return nil, false, fmt.Errorf("device certificate UserID %s does not match session identity %s",
			cert.UserID, s.Identity)
	}

	scope := cert.Scope.Send
	blocked := make([]delivery.SubmissionResult, 0)
	allowedCount := 0
	for _, addr := range recipients {
		address := string(addr)
		if scope.Allows(address) {
			allowedCount++
			continue
		}
		reasonText := fmt.Sprintf("recipient %s is outside the device's scope.send", address)
		if scope.Mode == keys.SendModeNone {
			reasonText = "device certificate scope.send.mode is 'none'"
		}
		blocked = append(blocked, delivery.SubmissionResult{
			Recipient:  address,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonScopeExceeded,
			Reason:     reasonText,
		})
		s.logf("[%s] scope_exceeded: envelope=%s recipient=%s mode=%s",
			s.Identity, envelopeID, address, scope.Mode)
	}
	allBlocked = allowedCount == 0 && len(recipients) > 0
	return blocked, allBlocked, nil
}

// signLocalResult applies the domain signatures required by
// CLIENT.md §3.3 / KEY.md §5.1 to a ResponseResult before the server
// returns it to a client.
//
// Two signatures are attached:
//
//  1. A per-record domain signature on every user Record in
//     result.UserKeys, via keys.SignRecord. This is the KEY.md §5.1
//     domain signature that the client's keys.Verifier checks
//     against the response's DomainKey.
//
//  2. A response-level OriginSignature on the whole result, via
//     keys.SignResponseResult. This is the CLIENT.md §5.4.5
//     "origin_signature" that a forwarding home server passes
//     through intact on cross-domain federation hops.
//
// Records are deep-copied before signing so we never mutate the
// store's shared copies — concurrent lookups on the same address
// from other goroutines would otherwise see signature bytes being
// appended under their feet.
func (s *Server) signLocalResult(result *keys.ResponseResult) error {
	if s.DomainSignPriv == nil {
		return errors.New("inboxd: no domain signing key")
	}
	signer := s.Suite.Signer()
	// Clone each user record and sign the clone.
	cloned := make([]*keys.Record, 0, len(result.UserKeys))
	for _, rec := range result.UserKeys {
		if rec == nil {
			continue
		}
		cp := *rec
		// Reset signatures to avoid carrying stale ones from the
		// store.
		cp.Signatures = nil
		if err := keys.SignRecord(signer, s.DomainSignPriv, s.LocalDomain, s.DomainSignFP, &cp); err != nil {
			return fmt.Errorf("sign user record %s: %w", rec.KeyID, err)
		}
		cloned = append(cloned, &cp)
	}
	result.UserKeys = cloned
	// Fill in OriginSignature LAST, after every other field of the
	// result is finalized, because SignResponseResult canonicalizes
	// everything except origin_signature.
	if err := keys.SignResponseResult(signer, s.DomainSignPriv, s.DomainSignFP, result); err != nil {
		return fmt.Errorf("sign response result: %w", err)
	}
	return nil
}

// cachedRemoteFetch fetches keys for addresses on peerDomain via the
// Forwarder. We do NOT currently cache the response — the demo reruns
// the fetch on every inbound client SEMP_KEYS request. A production
// implementation would cache per the remote TTL.
func (s *Server) cachedRemoteFetch(ctx context.Context, peerDomain string, addresses []string) (*keys.Response, error) {
	req := keys.NewRequest(newRequestID(), addresses)
	return s.Forwarder.FetchKeys(ctx, peerDomain, req)
}

// newRequestID returns a short pseudo-ULID for a SEMP_KEYS request.
// The caller only needs per-session uniqueness for correlation; we use
// a timestamp + a few random bytes to keep the function dependency-free.
func newRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// handleRekey processes a SEMP_REKEY init from the peer and runs the
// responder side of the rekey exchange (SESSION.md §3). The session's
// key material is rotated in-place on success; subsequent envelope
// handling uses the new K_env_mac via s.envMAC().
//
// If the Server has no live Session pointer, rekey is not supported
// on this connection and we return an error so the loop logs it. A
// production implementation would send a signed rekey_rejected with
// reason_code rekey_unsupported; the current helper does the same via
// RekeyHandler.Handle's reject path only when Session is non-nil.
func (s *Server) handleRekey(ctx context.Context, stream MessageStream, raw []byte) error {
	if s.Session == nil {
		// We have no live session state to rekey against. Drop the
		// message; the peer will retry or fall back to re-handshake.
		return errors.New("rekey not supported: no live session")
	}
	handler := &session.RekeyHandler{
		Suite:   s.Suite,
		Session: s.Session,
	}
	if err := handler.Handle(ctx, stream, raw); err != nil {
		return fmt.Errorf("rekey handle: %w", err)
	}
	s.logf("[%s] rekey ok: new session=%s rekey_count=%d",
		s.Identity, s.Session.ID, s.Session.RekeyCount)
	return nil
}

// handleFetch returns every waiting envelope for the authenticated identity.
func (s *Server) handleFetch(ctx context.Context, stream MessageStream, raw []byte) error {
	var req delivery.FetchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("parse fetch request: %w", err)
	}
	if req.Type != delivery.FetchType || req.Step != delivery.FetchStepRequest {
		return fmt.Errorf("unexpected fetch type/step: %s/%s", req.Type, req.Step)
	}
	queued := s.Inbox.Drain(s.Identity)
	out := make([]string, 0, len(queued))
	for _, payload := range queued {
		out = append(out, base64.StdEncoding.EncodeToString(payload))
	}
	s.logf("[%s] fetch returned %d envelope(s)", s.Identity, len(out))
	return sendJSON(ctx, stream, delivery.NewFetchResponse(out))
}

// isLocal reports whether address belongs to the local domain.
func (s *Server) isLocal(address string) bool {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return false
	}
	return strings.EqualFold(address[at+1:], s.LocalDomain)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger == nil {
		return
	}
	s.Logger.Printf(format, args...)
}

// sendJSON marshals v with encoding/json (NOT canonical) and writes the
// result to stream. Submission and fetch messages are not signed and do
// not need to round-trip through canonical form.
func sendJSON(ctx context.Context, stream MessageStream, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return stream.Send(ctx, b)
}

// peekType extracts the top-level `type` field from a SEMP wire message.
func peekType(raw []byte) (string, error) {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	return probe.Type, nil
}

// isClientClose reports whether err is a normal client-disconnect signal
// (EOF, normal closure, context cancellation). The transport bindings
// each wrap their close errors slightly differently; we sniff strings
// rather than depend on transport-specific error types so the loop stays
// transport-agnostic.
func isClientClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := err.Error()
	for _, marker := range []string{
		"EOF",
		"websocket: close",
		"StatusNormalClosure",
		"StatusGoingAway",
		"close frame",
		"use of closed",
		"connection reset",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// domainOf returns the domain part of a user address (the substring
// after the last '@'), or the empty string if the address has no '@'.
func domainOf(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return ""
	}
	return address[at+1:]
}

// decodeBase64 is a tiny wrapper around encoding/base64 that accepts
// either the standard or the raw (unpadded) encoding, so callers that
// receive keys published by different implementations do not need to
// guess about padding.
func decodeBase64(s string) ([]byte, error) {
	if b, err := base64Std.DecodeString(s); err == nil {
		return b, nil
	}
	return base64RawStd.DecodeString(s)
}

// dummyAccessor exists only so the time import stays referenced if a
// future revision adds a Timestamp field to the loop's outbound messages.
// (The current builds use time only via delivery.NewSubmissionResponse.)
var _ = time.Time{}
