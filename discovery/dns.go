package discovery

import "context"

// SRVRecord is a parsed _semp._tcp.<domain> SRV record (DISCOVERY.md §2.1).
type SRVRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// TXTCapabilities is the parsed companion TXT record (DISCOVERY.md §2.2).
//
//	"v=semp1;pq=ready;c=ws,h2,quic;f=groups,threads,reactions"
type TXTCapabilities struct {
	Version    string   // v=semp1
	PostQuantum string   // pq=ready | hybrid | none
	Transports []string // c=ws,h2,quic
	Features   []string // f=groups,...
	AuthMethods []string // auth=...
	// Unknown parameters MUST be ignored rather than treated as errors
	// (DISCOVERY.md §2.2). They are preserved here for diagnostics.
	Unknown map[string]string
}

// LookupSRV queries DNS for the _semp._tcp.<domain> SRV records and
// returns them in the order delivered by the resolver. Standard SRV
// semantics apply: lower priority is preferred, weight controls load
// distribution within a priority.
//
// TODO(DISCOVERY.md §2.1): implement using net.Resolver.LookupSRV.
func LookupSRV(ctx context.Context, domain string) ([]SRVRecord, error) {
	_, _ = ctx, domain
	return nil, nil
}

// LookupTXT queries DNS for the _semp._tcp.<domain> TXT capability record
// and returns the parsed result.
//
// TODO(DISCOVERY.md §2.2): implement using net.Resolver.LookupTXT and a
// `;`-delimited key=value parser.
func LookupTXT(ctx context.Context, domain string) (*TXTCapabilities, error) {
	_, _ = ctx, domain
	return nil, nil
}
