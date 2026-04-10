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

// Server holds the state needed to serve one connected client. A fresh
// Server is constructed per accepted connection by the demo binary.
type Server struct {
	// Suite is the negotiated cryptographic suite for this session. Same
	// value the handshake used.
	Suite crypto.Suite

	// Inbox is the shared in-memory queue. Multiple Server instances
	// (one per connection) write into the same Inbox.
	Inbox *delivery.Inbox

	// LocalDomain is the server's own domain. Recipients on this domain
	// are delivered locally; everyone else gets recipient_not_found.
	LocalDomain string

	// DomainSignFP and DomainSignPriv are the server's long-term
	// signing key, used to sign envelopes during submission.
	DomainSignFP   keys.Fingerprint
	DomainSignPriv []byte

	// DomainEncFP and DomainEncPriv are the server's domain encryption
	// keypair, used to unwrap K_brief from inbound envelopes so the
	// server can read brief.to and brief.from.
	DomainEncFP   keys.Fingerprint
	DomainEncPriv []byte

	// Identity is the authenticated client identity established by the
	// preceding handshake. Used to scope envelope fetches and to record
	// the sender on outbound envelopes.
	Identity string

	// EnvMAC is K_env_mac from the established session. Used by
	// envelope.Sign to compute seal.session_mac on the envelopes the
	// server signs on the client's behalf.
	EnvMAC []byte

	// Logger receives operational notes (one line per accepted/rejected
	// envelope, one line per fetch). May be nil to disable logging.
	Logger Logger
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
		default:
			s.logf("[%s] unsupported message type %q", s.Identity, msgType)
		}
	}
}

// handleSubmission processes one envelope upload.
func (s *Server) handleSubmission(ctx context.Context, stream MessageStream, raw []byte) error {
	env, err := envelope.Decode(raw)
	if err != nil {
		// Send a per-recipient rejection so the client knows the
		// envelope was malformed. We don't have an envelope_id, so we
		// emit a synthetic one.
		resp := delivery.NewSubmissionResponse("malformed", []delivery.SubmissionResult{{
			Recipient: s.Identity,
			Status:    semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:    err.Error(),
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("decode envelope: %w", err)
	}

	// The client transmits the envelope WITHOUT seal.signature or
	// seal.session_mac populated. The home server fills both in per
	// CLIENT.md §1.3 / ENVELOPE.md §7.1 step 8.
	if err := envelope.Sign(env, s.Suite, s.DomainSignPriv, s.EnvMAC); err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient: s.Identity,
			Status:    semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:    err.Error(),
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("sign envelope: %w", err)
	}

	// Unwrap the brief so we know who it's for. The server's domain
	// encryption key MUST be present in seal.brief_recipients (the
	// client put it there during composition).
	bf, err := envelope.OpenBrief(env, s.Suite, s.DomainEncFP, s.DomainEncPriv)
	if err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient: s.Identity,
			Status:    semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:    fmt.Sprintf("server cannot unwrap brief: %v", err),
		}})
		_ = sendJSON(ctx, stream, resp)
		return fmt.Errorf("open brief: %w", err)
	}

	// Re-encode the (now signed) envelope for storage.
	wire, err := envelope.Encode(env)
	if err != nil {
		return fmt.Errorf("re-encode envelope: %w", err)
	}

	// Build per-recipient results. Local recipients are delivered to
	// the in-memory inbox; remote recipients receive recipient_not_found
	// (no cross-domain routing in the demo).
	allRecipients := append([]brief.Address{}, bf.To...)
	allRecipients = append(allRecipients, bf.CC...)
	results := make([]delivery.SubmissionResult, 0, len(allRecipients))
	for _, addr := range allRecipients {
		address := string(addr)
		if !s.isLocal(address) {
			results = append(results, delivery.SubmissionResult{
				Recipient: address,
				Status:    semp.StatusRecipientNotFound,
				Reason:    "cross-domain delivery not implemented in this demo binary",
			})
			continue
		}
		s.Inbox.Store(address, wire)
		results = append(results, delivery.SubmissionResult{
			Recipient: address,
			Status:    semp.StatusDelivered,
		})
		s.logf("[%s] delivered envelope %s → %s", s.Identity, env.Postmark.ID, address)
	}

	resp := delivery.NewSubmissionResponse(env.Postmark.ID, results)
	return sendJSON(ctx, stream, resp)
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

// dummyAccessor exists only so the time import stays referenced if a
// future revision adds a Timestamp field to the loop's outbound messages.
// (The current builds use time only via delivery.NewSubmissionResponse.)
var _ = time.Time{}
