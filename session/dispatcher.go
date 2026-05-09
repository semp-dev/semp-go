package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MessageStream is the minimal interface Dispatch needs from a
// transport. transport.Conn satisfies it; tests can substitute an
// in-memory channel pair without pulling in the transport package.
type MessageStream interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
}

// Handlers maps SEMP message types to per-message handler callbacks.
// A Dispatch loop reads frames from a [MessageStream], parses the
// outer `type` field, and routes each frame to the matching handler.
//
// Handlers are protocol-pure: they accept raw bytes and return on
// completion or with a transport-level error. Application code
// composes Handlers with the per-type primitives this library exposes
// (envelope.Decode, keys.HandleRequest, session.RekeyResponder, etc.)
// to assemble a full server runtime.
//
// A Handler that is not registered for a given type is treated per
// the protocol's forward-compatibility rule: the frame is silently
// dropped unless [DispatchHandlers.OnUnknown] is set, in which case
// it is invoked with the parsed type string and raw frame.
type DispatchHandlers struct {
	// OnEnvelope handles a SEMP_ENVELOPE submission frame.
	OnEnvelope func(ctx context.Context, raw []byte) error

	// OnRekey handles a SEMP_REKEY frame.
	OnRekey func(ctx context.Context, raw []byte) error

	// OnKeys handles a SEMP_KEYS request or response frame.
	OnKeys func(ctx context.Context, raw []byte) error

	// OnFetch handles a SEMP_FETCH inbox-pull frame.
	OnFetch func(ctx context.Context, raw []byte) error

	// OnDiscovery handles a SEMP_DISCOVERY exchange frame.
	OnDiscovery func(ctx context.Context, raw []byte) error

	// OnDelivery handles SEMP_DELIVERY_ACK / SEMP_DELIVERY_RECEIPT
	// frames.
	OnDelivery func(ctx context.Context, raw []byte) error

	// OnUnknown is invoked when a frame's `type` field does not match
	// any registered handler. Default is "silently drop" per the
	// protocol forward-compatibility rule.
	OnUnknown func(ctx context.Context, msgType string, raw []byte) error

	// OnHandlerError is invoked on a non-fatal error from a registered
	// handler. The dispatch loop continues; the caller decides whether
	// to close the stream. Default is "swallow" — handler errors are
	// non-fatal by design.
	OnHandlerError func(err error, msgType string)
}

// Dispatch reads frames from stream and routes each to the matching
// handler in h. Returns io.EOF on clean stream close; returns the
// underlying error on transport failure or context cancellation.
//
// Dispatch is the post-handshake message-loop primitive. Higher-level
// runtimes (a server's per-session goroutine, a client's reactive
// event loop) call this with a configured [DispatchHandlers]; the
// per-type handlers themselves are caller-supplied.
//
// Dispatch is transport-agnostic — it consumes any [MessageStream]
// and never owns the underlying connection. The caller closes the
// stream when Dispatch returns.
func Dispatch(ctx context.Context, stream MessageStream, h DispatchHandlers) error {
	if stream == nil {
		return errors.New("session: nil message stream")
	}
	for {
		raw, err := stream.Recv(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return io.EOF
			}
			return fmt.Errorf("session: dispatch recv: %w", err)
		}
		msgType, err := peekType(raw)
		if err != nil {
			if h.OnHandlerError != nil {
				h.OnHandlerError(fmt.Errorf("malformed frame: %w", err), "")
			}
			continue
		}
		var handlerErr error
		switch msgType {
		case "SEMP_ENVELOPE":
			if h.OnEnvelope != nil {
				handlerErr = h.OnEnvelope(ctx, raw)
			}
		case "SEMP_REKEY":
			if h.OnRekey != nil {
				handlerErr = h.OnRekey(ctx, raw)
			}
		case "SEMP_KEYS":
			if h.OnKeys != nil {
				handlerErr = h.OnKeys(ctx, raw)
			}
		case "SEMP_FETCH":
			if h.OnFetch != nil {
				handlerErr = h.OnFetch(ctx, raw)
			}
		case "SEMP_DISCOVERY":
			if h.OnDiscovery != nil {
				handlerErr = h.OnDiscovery(ctx, raw)
			}
		case "SEMP_DELIVERY_ACK", "SEMP_DELIVERY_RECEIPT":
			if h.OnDelivery != nil {
				handlerErr = h.OnDelivery(ctx, raw)
			}
		default:
			if h.OnUnknown != nil {
				handlerErr = h.OnUnknown(ctx, msgType, raw)
			}
			// else silently drop, per protocol forward-compatibility.
		}
		if handlerErr != nil && h.OnHandlerError != nil {
			h.OnHandlerError(handlerErr, msgType)
		}
	}
}

// peekType extracts the outer JSON `type` field from a SEMP frame
// without unmarshalling the rest of the payload.
func peekType(raw []byte) (string, error) {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	return probe.Type, nil
}
