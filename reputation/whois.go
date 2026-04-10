package reputation

import (
	"context"
	"time"
)

// MinDomainAge is the recommended minimum domain registration age before
// a domain receives baseline trust per REPUTATION.md §2.1.
const MinDomainAge = 30 * 24 * time.Hour

// WHOIS is the interface that supplies domain registration age. Operators
// supply their own implementation — there is no de facto WHOIS library
// that is both reliable and free of rate limits, so this is intentionally
// pluggable.
type WHOIS interface {
	// RegistrationAge returns the time elapsed since the domain was first
	// registered, or an error if the lookup fails.
	RegistrationAge(ctx context.Context, domain string) (time.Duration, error)
}

// MeetsMinAge reports whether the given duration meets MinDomainAge.
func MeetsMinAge(age time.Duration) bool { return age >= MinDomainAge }
