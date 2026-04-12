package delivery

import (
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/envelope"
)

// InternalRouteType is the wire-level type discriminator for envelopes
// routed between partition servers within the same domain.
const InternalRouteType = "SEMP_INTERNAL_ROUTE"

// InternalRoute is the request envelope used when one partition server
// hands an envelope to a sibling partition server inside the same domain
// (DISCOVERY.md §5.4).
type InternalRoute struct {
	Type          string             `json:"type"`
	To            string             `json:"to"`
	InternalRoute []string           `json:"internal_route"`
	Timestamp     time.Time          `json:"timestamp"`
	Envelope      *envelope.Envelope `json:"envelope"`
}

// InternalRouteAck is the acknowledgment a receiving partition server
// returns for every internally routed envelope (DISCOVERY.md §5.4.1).
//
// Internal routing does NOT exempt an envelope from the delivery pipeline
// or from block list enforcement; the receiving partition server runs the
// full pipeline before producing this acknowledgment (DELIVERY.md §5.3).
type InternalRouteAck struct {
	Type       string              `json:"type"` // SEMP_INTERNAL_ROUTE
	Step       string              `json:"step"` // "acknowledgment"
	Version    string              `json:"version"`
	EnvelopeID string              `json:"envelope_id"`
	To         string              `json:"to"`
	Status     semp.Acknowledgment `json:"status"`
	ReasonCode semp.ReasonCode     `json:"reason_code,omitempty"`
	Reason     string              `json:"reason,omitempty"`
	Timestamp  time.Time           `json:"timestamp"`
}

// InternalRouteTimeout is the recommended timeout for internally routed
// deliveries before they are treated as silent (DISCOVERY.md §5.4.1,
// DELIVERY.md §1.5).
const InternalRouteTimeout = 30 * time.Second
