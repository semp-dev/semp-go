package discovery

import "context"

// LookupMX queries DNS for the recipient domain's MX records. Used as the
// SMTP capability check after SEMP discovery yields no result
// (DISCOVERY.md §7.2).
//
// If MX records are present, the discovery outcome is "legacy" and the
// home server returns legacy_required to the client. If no MX records are
// present, the outcome is "not_found" and the home server returns
// recipient_not_found.
//
// The MX check is DNS-only. The sender server MUST NOT attempt an SMTP
// connection during discovery.
//
// TODO(DISCOVERY.md §7.2): implement using net.Resolver.LookupMX.
func LookupMX(ctx context.Context, domain string) ([]string, error) {
	_, _ = ctx, domain
	return nil, nil
}
