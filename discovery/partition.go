package discovery

import "context"

// PartitionStrategy is the user-partitioning strategy advertised by a
// large domain via the _semp-partition.<domain> TXT record (DISCOVERY.md
// §2.4).
type PartitionStrategy string

// Defined strategies.
const (
	StrategyAlpha  PartitionStrategy = "alpha"
	StrategyHash   PartitionStrategy = "hash"
	StrategyLookup PartitionStrategy = "lookup"
)

// PartitionConfig is the parsed _semp-partition.<domain> TXT record.
type PartitionConfig struct {
	Version   string
	Strategy  PartitionStrategy
	Servers   int
	Algorithm string // for StrategyHash; e.g. "sha256"
}

// ResolvePartition returns the SEMP server hostname that handles the given
// user address according to config. For StrategyLookup, ResolvePartition
// queries the partition lookup server.
//
// TODO(DISCOVERY.md §2.4): implement all three strategies.
func ResolvePartition(ctx context.Context, config *PartitionConfig, address string) (string, error) {
	_, _, _ = ctx, config, address
	return "", nil
}
