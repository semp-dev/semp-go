package brief

// SplitForBCC materializes a Brief with BCC recipients into the set of
// per-recipient copies required by CLIENT.md §3.5 and ENVELOPE.md §5.3.
//
// The SEMP privacy model forbids server-side BCC stripping: a sending
// client MUST generate one distinct envelope copy per BCC recipient so
// that the bcc field contains only that recipient's address in each
// copy, and is absent entirely from the copy delivered to to/cc
// recipients. The sending server never sees the full BCC list.
//
// Returned copies:
//
//  1. If b.BCC is empty, the result is []*Brief{b} — a single copy,
//     returned unchanged. Callers may treat the returned slice as the
//     authoritative set whether or not there were BCC recipients.
//
//  2. Otherwise, the result has len(b.BCC)+1 elements:
//
//     - One "visible" copy intended for to + cc recipients. The copy
//       has bcc set to nil so the brief serializes without the bcc
//       field (brief.Brief uses json:"bcc,omitempty"). All other
//       fields match b byte-for-byte.
//
//     - One copy per original BCC recipient. Each copy has bcc
//       containing exactly that one address; to, cc, and every other
//       field are preserved so the recipient sees the same primary
//       recipient list as everyone else.
//
// The returned Briefs share the underlying Extensions map and Address
// slices with the input by value — callers that want to mutate each
// copy independently should clone first.
//
// Reference: CLIENT.md §3.5, ENVELOPE.md §5.3.
func SplitForBCC(b *Brief) []*Brief {
	if b == nil {
		return nil
	}
	if len(b.BCC) == 0 {
		return []*Brief{b}
	}
	out := make([]*Brief, 0, len(b.BCC)+1)

	// Copy 0: visible to/cc recipients. The bcc field is cleared so
	// the JSON encoder (with bcc,omitempty) drops it entirely.
	visible := *b
	visible.BCC = nil
	out = append(out, &visible)

	// Copies 1..N: one per BCC recipient, each carrying only that
	// recipient's address in bcc. The underlying []Address is a
	// fresh single-element slice so mutating one copy's BCC does
	// not leak across copies.
	for _, recipient := range b.BCC {
		bccCopy := *b
		bccCopy.BCC = []Address{recipient}
		out = append(out, &bccCopy)
	}
	return out
}
