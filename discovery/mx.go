package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// LookupMX queries DNS for the recipient domain's MX records. Used as the
// SMTP capability check after SEMP discovery yields no result
// (DISCOVERY.md §7.2).
//
// If MX records are present, the discovery outcome is "legacy" and the
// home server returns legacy_required to the client. If no MX records
// are present, the outcome is "not_found" and the home server returns
// recipient_not_found.
//
// The MX check is DNS-only. The sender server MUST NOT attempt an SMTP
// connection during discovery.
//
// Returned values are the MX target hostnames (trailing dots removed),
// sorted by the DNS resolver in preference order.
func LookupMX(ctx context.Context, domain string) ([]string, error) {
	return LookupMXWith(ctx, DefaultDNSLookup(), domain)
}

// LookupMXWith is the injectable variant of LookupMX.
func LookupMXWith(ctx context.Context, lookup DNSLookup, domain string) ([]string, error) {
	if lookup == nil {
		return nil, errors.New("discovery: nil DNS lookup")
	}
	mxs, err := lookup.LookupMX(ctx, domain)
	if err != nil {
		// net.DefaultResolver returns an error (not an empty slice)
		// when no records exist. Surface the underlying error so
		// callers can branch on NXDOMAIN vs. temporary failure.
		return nil, fmt.Errorf("discovery: MX lookup for %s: %w", domain, err)
	}
	out := make([]string, 0, len(mxs))
	for _, m := range mxs {
		if m == nil {
			continue
		}
		out = append(out, strings.TrimSuffix(m.Host, "."))
	}
	return out, nil
}

// sortedMXHosts is a tiny helper that returns MX hostnames from the
// raw net.MX records in the order the resolver delivered them. Kept
// exported so future code that wants preference-ordered MX records
// without LookupMXWith's error handling has a shared path.
func sortedMXHosts(raw []*net.MX) []string {
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		if m == nil {
			continue
		}
		out = append(out, strings.TrimSuffix(m.Host, "."))
	}
	return out
}
