package brief

// Address is a SEMP user address. The wire format is `user@domain`,
// matching SMTP-style addressing. SEMP is UTF-8 native (FAQ §1.11), so the
// local part and domain may contain any valid UTF-8.
//
// The Address type is a string alias rather than a struct so that it
// marshals trivially to JSON without any custom MarshalJSON shim. Parsing
// helpers are provided as standalone functions.
type Address string

// String satisfies fmt.Stringer.
func (a Address) String() string { return string(a) }

// Local returns the local part of the address (everything before the final
// '@'). Returns the entire string if no '@' is present.
//
// TODO(ENVELOPE.md §5): handle quoted local parts and edge cases.
func (a Address) Local() string {
	s := string(a)
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '@' {
			return s[:i]
		}
	}
	return s
}

// Domain returns the domain part of the address (everything after the final
// '@'). Returns the empty string if no '@' is present.
func (a Address) Domain() string {
	s := string(a)
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '@' {
			return s[i+1:]
		}
	}
	return ""
}

// Validate reports an error if the address is not syntactically valid.
//
// TODO(ENVELOPE.md §5): implement strict UTF-8 + structural validation.
func (a Address) Validate() error {
	_ = a
	return nil
}
