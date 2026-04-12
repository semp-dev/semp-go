package handshake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"semp.dev/semp-go/session"
)

// MessageStream is the minimal interface a handshake driver needs from a
// transport. Any transport.Conn satisfies it; the handshake package
// intentionally does NOT import transport directly so that the layering
// stays one-way (transport bindings depend on handshake, never the other
// way round).
type MessageStream interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
}

// RunClient drives a client-side handshake to completion over stream.
//
// Sequence (HANDSHAKE.md §2.1):
//
//  1. Send init
//  2. Recv response (or challenge interstitial — handled transparently)
//  3. Send confirm
//  4. Recv accepted (or rejected)
//
// On success, returns the established *session.Session.
//
// On any handshake-layer rejection received from the server, the returned
// error wraps a *handshakeRejection so callers can inspect the reason code
// via errors.As / errors.Is.
//
// On any transport-layer error, the connection is left to the caller to
// close. RunClient does not call stream.Close.
func RunClient(ctx context.Context, stream MessageStream, c *Client) (*session.Session, error) {
	if stream == nil {
		return nil, errors.New("handshake: nil stream")
	}
	if c == nil {
		return nil, errors.New("handshake: nil client")
	}

	initBytes, err := c.Init()
	if err != nil {
		return nil, fmt.Errorf("handshake: client init: %w", err)
	}
	if err := stream.Send(ctx, initBytes); err != nil {
		return nil, fmt.Errorf("handshake: send init: %w", err)
	}

	// Loop to absorb the optional challenge interstitial.
	for {
		incoming, err := stream.Recv(ctx)
		if err != nil {
			return nil, fmt.Errorf("handshake: recv response: %w", err)
		}
		step, err := peekStep(incoming)
		if err != nil {
			return nil, err
		}
		switch step {
		case StepChallenge:
			solution, err := c.OnChallenge(incoming)
			if err != nil {
				return nil, fmt.Errorf("handshake: solve challenge: %w", err)
			}
			if err := stream.Send(ctx, solution); err != nil {
				return nil, fmt.Errorf("handshake: send challenge_response: %w", err)
			}
			continue
		case StepRejected:
			return nil, c.OnRejected(incoming)
		case StepResponse:
			confirmBytes, sess, err := c.OnResponse(incoming)
			if err != nil {
				return nil, fmt.Errorf("handshake: client OnResponse: %w", err)
			}
			if err := stream.Send(ctx, confirmBytes); err != nil {
				return nil, fmt.Errorf("handshake: send confirm: %w", err)
			}
			final, err := stream.Recv(ctx)
			if err != nil {
				return nil, fmt.Errorf("handshake: recv accepted: %w", err)
			}
			finalStep, err := peekStep(final)
			if err != nil {
				return nil, err
			}
			switch finalStep {
			case StepAccepted:
				if err := c.OnAccepted(final, sess); err != nil {
					return nil, fmt.Errorf("handshake: client OnAccepted: %w", err)
				}
				return sess, nil
			case StepRejected:
				return nil, c.OnRejected(final)
			default:
				return nil, fmt.Errorf("handshake: unexpected final step %q", finalStep)
			}
		default:
			return nil, fmt.Errorf("handshake: unexpected step %q in client driver", step)
		}
	}
}

// RunServer drives a server-side handshake to completion over stream.
//
// Sequence (HANDSHAKE.md §2.1):
//
//  1. Recv init
//  2. Send response (or challenge interstitial — handled transparently)
//  3. Recv confirm
//  4. Send accepted
//
// On any error from the handshake state machine, RunServer attempts to
// send a signed Rejected message before returning. The session_id will
// be empty if the failure occurred before the response was generated.
//
// As with RunClient, the caller owns the connection lifecycle.
func RunServer(ctx context.Context, stream MessageStream, s *Server) (*session.Session, error) {
	if stream == nil {
		return nil, errors.New("handshake: nil stream")
	}
	if s == nil {
		return nil, errors.New("handshake: nil server")
	}

	// 1. Recv init.
	initBytes, err := stream.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("handshake: recv init: %w", err)
	}

	// 2. Process init. May return Challenge bytes.
	out, err := s.OnInit(initBytes)
	if err != nil {
		_ = sendRejection(ctx, stream, s, "policy_violation", err.Error())
		return nil, fmt.Errorf("handshake: server OnInit: %w", err)
	}
	if err := stream.Send(ctx, out); err != nil {
		return nil, fmt.Errorf("handshake: send response: %w", err)
	}

	// If we just sent a challenge, the next message from the client
	// is a challenge_response and we need to advance the handshake.
	step, err := peekStep(out)
	if err != nil {
		return nil, err
	}
	if step == StepChallenge {
		solution, err := stream.Recv(ctx)
		if err != nil {
			return nil, fmt.Errorf("handshake: recv challenge_response: %w", err)
		}
		respBytes, err := s.OnChallengeResponse(solution)
		if err != nil {
			_ = sendRejection(ctx, stream, s, "challenge_failed", err.Error())
			return nil, fmt.Errorf("handshake: server OnChallengeResponse: %w", err)
		}
		if err := stream.Send(ctx, respBytes); err != nil {
			return nil, fmt.Errorf("handshake: send response after challenge: %w", err)
		}
	}

	// 3. Recv confirm.
	confirmBytes, err := stream.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("handshake: recv confirm: %w", err)
	}

	// 4. Process confirm and send accepted.
	acceptedBytes, sess, err := s.OnConfirm(confirmBytes)
	if err != nil {
		_ = sendRejection(ctx, stream, s, "auth_failed", err.Error())
		return nil, fmt.Errorf("handshake: server OnConfirm: %w", err)
	}
	if err := stream.Send(ctx, acceptedBytes); err != nil {
		return nil, fmt.Errorf("handshake: send accepted: %w", err)
	}
	return sess, nil
}

// RunInitiator drives a federation initiator handshake to completion
// over stream. Symmetric to RunClient but uses the federation message
// types (HANDSHAKE.md §5.1). On success, returns the established
// *session.Session for the federation hop.
func RunInitiator(ctx context.Context, stream MessageStream, i *Initiator) (*session.Session, error) {
	if stream == nil {
		return nil, errors.New("handshake: nil stream")
	}
	if i == nil {
		return nil, errors.New("handshake: nil initiator")
	}
	initBytes, err := i.Init()
	if err != nil {
		return nil, fmt.Errorf("handshake: initiator init: %w", err)
	}
	if err := stream.Send(ctx, initBytes); err != nil {
		return nil, fmt.Errorf("handshake: send federation init: %w", err)
	}
	respBytes, err := stream.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("handshake: recv federation response: %w", err)
	}
	step, err := peekStep(respBytes)
	if err != nil {
		return nil, err
	}
	if step == StepRejected {
		return nil, i.OnRejected(respBytes)
	}
	if step != StepResponse {
		return nil, fmt.Errorf("handshake: unexpected step %q in federation initiator", step)
	}
	confirmBytes, sess, err := i.OnResponse(respBytes)
	if err != nil {
		return nil, fmt.Errorf("handshake: initiator OnResponse: %w", err)
	}
	if err := stream.Send(ctx, confirmBytes); err != nil {
		return nil, fmt.Errorf("handshake: send federation confirm: %w", err)
	}
	acceptedBytes, err := stream.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("handshake: recv federation accepted: %w", err)
	}
	finalStep, err := peekStep(acceptedBytes)
	if err != nil {
		return nil, err
	}
	switch finalStep {
	case StepAccepted:
		if err := i.OnAccepted(acceptedBytes, sess); err != nil {
			return nil, fmt.Errorf("handshake: initiator OnAccepted: %w", err)
		}
		return sess, nil
	case StepRejected:
		return nil, i.OnRejected(acceptedBytes)
	default:
		return nil, fmt.Errorf("handshake: unexpected final step %q in federation initiator", finalStep)
	}
}

// RunResponder drives a federation responder handshake to completion
// over stream. Symmetric to RunServer but uses the federation message
// types. Any error from the state machine triggers a signed Rejected
// before returning.
func RunResponder(ctx context.Context, stream MessageStream, r *Responder) (*session.Session, error) {
	if stream == nil {
		return nil, errors.New("handshake: nil stream")
	}
	if r == nil {
		return nil, errors.New("handshake: nil responder")
	}
	initBytes, err := stream.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("handshake: recv federation init: %w", err)
	}
	respBytes, err := r.OnInit(initBytes)
	if err != nil {
		_ = sendFederationRejection(ctx, stream, r, "policy_violation", err.Error())
		return nil, fmt.Errorf("handshake: responder OnInit: %w", err)
	}
	if err := stream.Send(ctx, respBytes); err != nil {
		return nil, fmt.Errorf("handshake: send federation response: %w", err)
	}
	confirmBytes, err := stream.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("handshake: recv federation confirm: %w", err)
	}
	acceptedBytes, sess, err := r.OnConfirm(confirmBytes)
	if err != nil {
		_ = sendFederationRejection(ctx, stream, r, "auth_failed", err.Error())
		return nil, fmt.Errorf("handshake: responder OnConfirm: %w", err)
	}
	if err := stream.Send(ctx, acceptedBytes); err != nil {
		return nil, fmt.Errorf("handshake: send federation accepted: %w", err)
	}
	return sess, nil
}

func sendFederationRejection(ctx context.Context, stream MessageStream, r *Responder, code, reason string) error {
	rej, err := r.NewRejection(code, reason)
	if err != nil {
		return err
	}
	return stream.Send(ctx, rej)
}

// peekStep extracts the `step` field from a SEMP_HANDSHAKE message
// without fully unmarshaling the rest of the structure. Used by the
// drivers to dispatch on which message variant just arrived.
func peekStep(data []byte) (Step, error) {
	var probe struct {
		Type string `json:"type"`
		Step Step   `json:"step"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("handshake: peek step: %w", err)
	}
	if probe.Type != MessageType {
		return "", fmt.Errorf("handshake: unexpected message type %q", probe.Type)
	}
	return probe.Step, nil
}

// sendRejection is a best-effort helper that builds a signed Rejected
// message and writes it to stream. It silently swallows any error from
// the build or send because the caller is already in an error path; the
// rejection is purely informational from the server's perspective.
func sendRejection(ctx context.Context, stream MessageStream, s *Server, code, reason string) error {
	rej, err := s.NewRejection(code, reason)
	if err != nil {
		return err
	}
	return stream.Send(ctx, rej)
}
