package handshake

import (
	"context"
	"errors"
	"fmt"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/session"
)

// RunClientResume drives a client-side resume exchange to completion
// over stream per HANDSHAKE.md §2.8.2:
//
//  1. Send Resume(ticket).
//  2. Recv Accepted | Rejected.
//
// On Accepted, returns the resumed *session.Session and the new
// opaque ticket bytes the server issued for chaining a future
// resume. The caller stores the new ticket alongside the session
// for the next reconnect.
//
// On Rejected with reason `resumption_failed` (or any §2.8.5
// fallback signal), returns an error that satisfies
// IsResumptionFailed; the caller MUST discard the resume attempt
// and fall back to a fresh full handshake. RunClientResumeOrFull
// composes this for callers who want one-call fallback.
//
// On any transport error, the returned error wraps the underlying
// cause; the caller decides whether to retry or escalate. The
// stream is left open; RunClientResume does not call stream.Close.
func RunClientResume(ctx context.Context, stream MessageStream, c *Client, ticket []byte) (*session.Session, []byte, error) {
	if stream == nil {
		return nil, nil, errors.New("handshake: nil stream")
	}
	if c == nil {
		return nil, nil, errors.New("handshake: nil client")
	}
	if len(ticket) == 0 {
		return nil, nil, errors.New("handshake: empty resumption ticket")
	}

	resumeBytes, err := c.Resume(ticket)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: client resume: %w", err)
	}
	if err := stream.Send(ctx, resumeBytes); err != nil {
		return nil, nil, fmt.Errorf("handshake: send resume: %w", err)
	}
	respBytes, err := stream.Recv(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: recv resume response: %w", err)
	}
	step, err := peekStep(respBytes)
	if err != nil {
		return nil, nil, err
	}
	switch step {
	case StepAccepted:
		sess, newTicket, err := c.OnResumeAccepted(respBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("handshake: client OnResumeAccepted: %w", err)
		}
		return sess, newTicket, nil
	case StepRejected:
		return nil, nil, c.OnRejected(respBytes)
	default:
		return nil, nil, fmt.Errorf("handshake: unexpected step %q in resume response", step)
	}
}

// RunInitiatorResume drives a federation initiator resume exchange
// to completion over stream. Symmetric to RunClientResume but uses
// the federation message types.
//
// peerConfigurationRevision is the SEMP_CONFIGURATION revision the
// initiator's discovery cache has for the recipient domain; the
// responder rejects with `configuration_stale` if it has emitted a
// later revision since the ticket was issued.
//
// Returns (session, newTicket) on success; an error satisfying
// IsResumptionFailed on §2.8.5 fallback.
func RunInitiatorResume(ctx context.Context, stream MessageStream, i *Initiator, ticket []byte, peerConfigurationRevision int) (*session.Session, []byte, error) {
	if stream == nil {
		return nil, nil, errors.New("handshake: nil stream")
	}
	if i == nil {
		return nil, nil, errors.New("handshake: nil initiator")
	}
	if len(ticket) == 0 {
		return nil, nil, errors.New("handshake: empty federation resumption ticket")
	}

	resumeBytes, err := i.Resume(ticket, peerConfigurationRevision)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: initiator resume: %w", err)
	}
	if err := stream.Send(ctx, resumeBytes); err != nil {
		return nil, nil, fmt.Errorf("handshake: send federation resume: %w", err)
	}
	respBytes, err := stream.Recv(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: recv federation resume response: %w", err)
	}
	step, err := peekStep(respBytes)
	if err != nil {
		return nil, nil, err
	}
	switch step {
	case StepAccepted:
		sess, newTicket, err := i.OnResumeAccepted(respBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("handshake: initiator OnResumeAccepted: %w", err)
		}
		return sess, newTicket, nil
	case StepRejected:
		return nil, nil, i.OnRejected(respBytes)
	default:
		return nil, nil, fmt.Errorf("handshake: unexpected step %q in federation resume response", step)
	}
}

// RunClientResumeOrFull tries a resume against the supplied stream
// and ticket per HANDSHAKE.md §2.8.5. If the resume fails with a
// reason that warrants fallback (resumption_failed, plus any other
// §2.8.5 fallback signal), it discards the resume attempt and
// performs a full handshake against a fresh stream + Client supplied
// by the caller.
//
// The caller supplies factories rather than reusing the prior
// stream / Client because:
//
//   - The prior stream was already used for the failed Resume
//     exchange; protocols like HTTP/2 and WebSockets typically open
//     a new stream per logical handshake.
//   - The prior Client has accumulated state from Resume that would
//     interfere with a fresh Init; reusing it would corrupt the
//     handshake.
//
// On success returns (session, newTicket, isFallback) where
// isFallback is true if the function fell back to a full handshake.
//
// Errors from either path are returned wrapped with context; the
// caller can branch on whether the resume was the failure point or
// the fallback was.
func RunClientResumeOrFull(
	ctx context.Context,
	resumeStream MessageStream,
	resumeClient *Client,
	ticket []byte,
	freshStream func() (MessageStream, error),
	freshClient func() (*Client, error),
) (*session.Session, []byte, bool, error) {
	sess, newTicket, err := RunClientResume(ctx, resumeStream, resumeClient, ticket)
	if err == nil {
		return sess, newTicket, false, nil
	}
	if !IsResumptionFailed(err) {
		return nil, nil, false, fmt.Errorf("handshake: resume: %w", err)
	}
	if freshStream == nil || freshClient == nil {
		return nil, nil, false, fmt.Errorf("handshake: resume failed and no fallback factory supplied: %w", err)
	}
	stream, ferr := freshStream()
	if ferr != nil {
		return nil, nil, false, fmt.Errorf("handshake: resume fallback stream: %w", ferr)
	}
	c, ferr := freshClient()
	if ferr != nil {
		return nil, nil, false, fmt.Errorf("handshake: resume fallback client: %w", ferr)
	}
	sess, fullErr := RunClient(ctx, stream, c)
	if fullErr != nil {
		return nil, nil, true, fmt.Errorf("handshake: resume fallback full handshake: %w", fullErr)
	}
	// On a successful full handshake, the new ticket (if the server
	// issued one) is on the session; surface its raw bytes via
	// session.Resumption (the existing API for retrieving the ticket
	// keying material). Callers that need the opaque ticket bytes
	// should inspect the session via the existing accessors.
	return sess, nil, true, nil
}

// IsResumptionFailed reports whether err signals that a resume
// attempt failed and the caller SHOULD fall back to a full
// handshake per §2.8.5. Returns true for:
//
//   - A wrapped *handshakeRejection whose Code is
//     "resumption_failed".
//   - A wrapped *handshakeRejection whose Code is
//     "configuration_stale" (federation §5.1.5: peer's published
//     configuration has rotated; the prior ticket is no longer
//     valid against the new domain key).
//   - A wrapped *handshakeRejection whose Code is "no_session"
//     (the ticket cache evicted the entry); §2.8.5 lists this as
//     a fallback trigger.
func IsResumptionFailed(err error) bool {
	if err == nil {
		return false
	}
	var rej *handshakeRejection
	if !errors.As(err, &rej) {
		return false
	}
	switch rej.Code {
	case string(semp.ReasonResumptionFailed),
		"configuration_stale",
		string(semp.ReasonNoSession):
		return true
	}
	return false
}

// RejectionCode returns the reason_code of err if err wraps a
// handshake rejection. Returns ("", false) for non-rejection errors.
// Useful for callers that want to branch on a specific code beyond
// the IsResumptionFailed predicate.
func RejectionCode(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	var rej *handshakeRejection
	if !errors.As(err, &rej) {
		return "", false
	}
	return rej.Code, true
}
