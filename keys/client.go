package keys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// ClientStream is the minimal interface a Fetcher needs from a
// transport. Both transport.Conn and the handshake/inboxd
// MessageStream interfaces satisfy it structurally; the keys package
// intentionally does not import transport directly to keep the layering
// one-way.
type ClientStream interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
}

// Fetcher is a tiny client-side wrapper that sends a SEMP_KEYS request
// over an authenticated session and returns the parsed response. It
// does not perform any signature verification on the returned key
// records — that is the caller's responsibility (per CLIENT.md §5.4.5).
type Fetcher struct {
	// Stream is the authenticated session to the home server. Must be
	// set before calling FetchKeys.
	Stream ClientStream
}

// NewFetcher constructs a Fetcher bound to the given stream.
func NewFetcher(stream ClientStream) *Fetcher {
	return &Fetcher{Stream: stream}
}

// FetchKeys sends req over the configured stream and waits for the
// matching response. The returned Response carries one ResponseResult
// per requested address. Errors are transport-level or parsing; a
// per-address lookup failure is reported in ResponseResult.Status
// (keys.StatusNotFound or keys.StatusError), not as an error here.
func (f *Fetcher) FetchKeys(ctx context.Context, req *Request) (*Response, error) {
	if f == nil || f.Stream == nil {
		return nil, errors.New("keys: fetcher has no stream")
	}
	if req == nil {
		return nil, errors.New("keys: nil request")
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal request: %w", err)
	}
	if err := f.Stream.Send(ctx, reqBytes); err != nil {
		return nil, fmt.Errorf("keys: send request: %w", err)
	}
	respRaw, err := f.Stream.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("keys: recv response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("keys: parse response: %w", err)
	}
	if resp.Type != RequestType || resp.Step != RequestStepResponse {
		return nil, fmt.Errorf("keys: unexpected response type/step: %s/%s", resp.Type, resp.Step)
	}
	return &resp, nil
}
