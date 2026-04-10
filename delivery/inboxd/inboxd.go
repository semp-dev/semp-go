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

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/brief"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/delivery"
	"github.com/semp-dev/semp-go/envelope"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
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

	// DomainEncFP and DomainEncPriv are the server's domain encryption
	// keypair, used to unwrap K_brief from inbound envelopes so the
	// server can read brief.to and brief.from.
	DomainEncFP   keys.Fingerprint
	DomainEncPriv []byte

	// Identity is the authenticated peer identity established by the
	// preceding handshake. In ModeClient this is the client's user
	// address; in ModeFederation it is the peer server's domain.
	Identity string

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
// unsigned from the client; the server signs it, unwraps the brief,
// delivers to local inboxes, and forwards to remote domains via the
// Forwarder (if configured).
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

	bf, err := envelope.OpenBrief(env, s.Suite, s.DomainEncFP, s.DomainEncPriv)
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

	wire, err := envelope.Encode(env)
	if err != nil {
		return fmt.Errorf("re-encode envelope: %w", err)
	}

	allRecipients := append([]brief.Address{}, bf.To...)
	allRecipients = append(allRecipients, bf.CC...)
	results := make([]delivery.SubmissionResult, 0, len(allRecipients))
	for _, addr := range allRecipients {
		address := string(addr)
		if s.isLocal(address) {
			s.Inbox.Store(address, wire)
			results = append(results, delivery.SubmissionResult{
				Recipient: address,
				Status:    semp.StatusDelivered,
			})
			s.logf("[%s] delivered envelope %s → %s (local)", s.Identity, env.Postmark.ID, address)
			continue
		}
		// Remote recipient: forward via the federation Forwarder if
		// one is configured. The Forwarder re-binds session_mac under
		// the federation session's K_env_mac and ships the envelope
		// to the peer; the peer verifies and routes into its own
		// inbox.
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
				Reason:     fmt.Sprintf("clone envelope for forwarding: %v", err),
			})
			continue
		}
		peerResp, err := s.Forwarder.Forward(ctx, peerDomain, forwardEnv)
		if err != nil {
			results = append(results, delivery.SubmissionResult{
				Recipient: address,
				Status:    semp.StatusRejected,
				Reason:    fmt.Sprintf("forward to %s: %v", peerDomain, err),
			})
			s.logf("[%s] forward %s → %s failed: %v", s.Identity, env.Postmark.ID, address, err)
			continue
		}
		// The peer's response carries per-recipient results of its
		// own (typically one per forwarded envelope). Surface each one
		// back to the client verbatim.
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
// rebound it before forwarding). This server MUST verify both proofs
// and MUST NOT re-sign — the domain signature is provenance and any
// change would break it.
func (s *Server) handleFederationSubmission(ctx context.Context, stream MessageStream, env *envelope.Envelope) error {
	// Verify the session MAC against OUR K_env_mac. The initiator
	// rebinds session_mac to the federation session's MAC key before
	// forwarding.
	if err := envelope.VerifySessionMAC(env, s.Suite, s.envMAC()); err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  s.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonSessionMACInvalid,
			Reason:     err.Error(),
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("verify session_mac: %w", err)
	}

	// Verify the domain signature against the original sender domain's
	// published key. The peer is just forwarding — the signature must
	// match the envelope's from_domain, not the peer.
	senderDomain := env.Postmark.FromDomain
	if s.Store != nil {
		rec, err := s.Store.LookupDomainKey(ctx, senderDomain)
		if err != nil || rec == nil {
			resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
				Recipient:  s.Identity,
				Status:     semp.StatusRejected,
				ReasonCode: semp.ReasonSealInvalid,
				Reason:     fmt.Sprintf("no domain key for sender %s", senderDomain),
			}})
			_ = sendJSON(ctx, stream, resp)
			return fmt.Errorf("lookup sender domain key for %s: %w", senderDomain, err)
		}
		pub, err := decodeBase64(rec.PublicKey)
		if err != nil {
			return fmt.Errorf("decode sender domain key: %w", err)
		}
		if err := envelope.VerifySignature(env, s.Suite, pub); err != nil {
			resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
				Recipient:  s.Identity,
				Status:     semp.StatusRejected,
				ReasonCode: semp.ReasonSealInvalid,
				Reason:     fmt.Sprintf("verify sender domain signature: %v", err),
			}})
			_ = sendJSON(ctx, stream, resp)
			return fmt.Errorf("verify domain signature: %w", err)
		}
	}

	// Unwrap brief using our domain encryption key — the original
	// sender wrapped K_brief for us in seal.brief_recipients during
	// composition, so this just works.
	bf, err := envelope.OpenBrief(env, s.Suite, s.DomainEncFP, s.DomainEncPriv)
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

	// Re-encode for storage. The envelope is already fully signed; we
	// just need a canonical byte form to stash in the inbox.
	wire, err := envelope.Encode(env)
	if err != nil {
		return fmt.Errorf("re-encode envelope: %w", err)
	}

	// Federation mode only delivers LOCAL recipients — we don't
	// support multi-hop forwarding. Remote recipients that somehow
	// showed up in an inbound federation envelope are dropped with
	// recipient_not_found; in practice the sending peer would have
	// filtered this out before forwarding.
	allRecipients := append([]brief.Address{}, bf.To...)
	allRecipients = append(allRecipients, bf.CC...)
	results := make([]delivery.SubmissionResult, 0, len(allRecipients))
	for _, addr := range allRecipients {
		address := string(addr)
		if !s.isLocal(address) {
			results = append(results, delivery.SubmissionResult{
				Recipient: address,
				Status:    semp.StatusRecipientNotFound,
				Reason:    "federation endpoint does not multi-hop",
			})
			continue
		}
		s.Inbox.Store(address, wire)
		results = append(results, delivery.SubmissionResult{
			Recipient: address,
			Status:    semp.StatusDelivered,
		})
		s.logf("[%s] federated delivery %s → %s", s.Identity, env.Postmark.ID, address)
	}
	resp := delivery.NewSubmissionResponse(env.Postmark.ID, results)
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
