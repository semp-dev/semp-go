package transport

import "context"

// FallbackTimeout is the per-transport dial timeout recommended by
// TRANSPORT.md §5.4 before moving to the next transport.
const FallbackTimeout = 10 // seconds, intentionally an int for use with time.Second multiplication.

// RecommendedFallbackOrder is the priority list from TRANSPORT.md §5.3:
// QUIC > WebSocket > HTTP/2 > gRPC. The connecting party SHOULD prefer
// transports earlier in this list when multiple are mutually supported,
// unless operational context dictates otherwise.
var RecommendedFallbackOrder = []ID{
	IDQUIC,
	IDWebSocket,
	IDHTTP2,
	IDgRPC,
}

// Fallback attempts to dial endpoint over each of the supplied transports
// in order. The first successful dial wins; failures cause a sequential
// move to the next transport. If all transports fail, Fallback returns the
// last error wrapped with TRANSPORT.md's "transport_exhausted" semantics.
//
// Fallback attempts MUST be sequential, not concurrent (TRANSPORT.md §5.4).
//
// TODO(TRANSPORT.md §5.4): implement, including the per-transport
// FallbackTimeout and the cache invalidation rule from §5.6.
func Fallback(ctx context.Context, endpoint string, candidates []Transport) (Conn, error) {
	_, _, _ = ctx, endpoint, candidates
	return nil, nil
}

// Order returns candidates sorted by RecommendedFallbackOrder. Transports
// not in the recommended list are placed at the end in their original order.
func Order(candidates []Transport) []Transport {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]Transport, 0, len(candidates))
	used := make(map[ID]bool, len(candidates))
	for _, want := range RecommendedFallbackOrder {
		for _, t := range candidates {
			if t.ID() == want && !used[t.ID()] {
				out = append(out, t)
				used[t.ID()] = true
			}
		}
	}
	for _, t := range candidates {
		if !used[t.ID()] {
			out = append(out, t)
			used[t.ID()] = true
		}
	}
	return out
}
