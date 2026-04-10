package brief

// SplitForBCC is the policy helper that produces one Brief per recipient
// when BCC recipients are present. The result is a slice of Briefs, each
// suitable for use as the source of an independent envelope copy:
//
//   - One copy that goes to all To and CC recipients with BCC absent.
//   - One copy per BCC recipient containing only that recipient's address
//     in BCC. The To and CC fields are preserved so the BCC recipient sees
//     the same primary recipient list as the To/CC recipients.
//
// SEMP enforces BCC privacy at the client by generating these per-recipient
// copies; the sending server never sees the full BCC list. Clients MUST NOT
// rely on server-side BCC stripping (CLIENT.md §3.5, ENVELOPE.md §5.3).
//
// TODO(CLIENT.md §3.5): implement; the skeleton returns a slice containing
// the input unchanged.
func SplitForBCC(b *Brief) []*Brief {
	if b == nil {
		return nil
	}
	if len(b.BCC) == 0 {
		return []*Brief{b}
	}
	return []*Brief{b}
}
