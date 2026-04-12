package brief_test

import (
	"strings"
	"testing"

	"semp.dev/semp-go/brief"
)

// FuzzAddressParse feeds arbitrary strings into brief.Address and
// exercises every accessor. The invariants:
//
//  1. No accessor ever panics on arbitrary UTF-8 (or non-UTF-8) input.
//  2. If the raw string contains an '@', Local() + "@" + Domain() must
//     reconstruct the original string.
//  3. If the raw string contains no '@', Local() returns the whole
//     string and Domain() returns "".
//  4. String() is the identity.
//  5. Validate() never panics.
func FuzzAddressParse(f *testing.F) {
	f.Add("")
	f.Add("alice@example.com")
	f.Add("user.with.dots@sub.example.co.uk")
	f.Add("utf8ユーザー@example.jp")
	f.Add("@just-domain")
	f.Add("no-domain@")
	f.Add("double@@at")
	f.Add("\x00\xff")
	f.Add("spaces are fine@host")

	f.Fuzz(func(t *testing.T, raw string) {
		a := brief.Address(raw)

		// String identity.
		if got := a.String(); got != raw {
			t.Errorf("String() = %q, want %q", got, raw)
		}

		local := a.Local()
		domain := a.Domain()

		if strings.ContainsRune(raw, '@') {
			// Reconstruction: the last '@' splits the string, so
			// Local + "@" + Domain should round-trip byte-for-byte.
			recon := local + "@" + domain
			if recon != raw {
				t.Errorf("Local+@+Domain = %q, want %q", recon, raw)
			}
		} else {
			if local != raw {
				t.Errorf("Local() = %q, want %q (no '@' present)", local, raw)
			}
			if domain != "" {
				t.Errorf("Domain() = %q, want empty (no '@' present)", domain)
			}
		}

		// Validate should never panic; we don't care whether it
		// accepts or rejects the address — we just want the call to
		// return.
		_ = a.Validate()
	})
}
