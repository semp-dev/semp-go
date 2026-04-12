module github.com/semp-dev/semp-go

// The minimum Go version required to build this module. Bumped to 1.25
// because golang.org/x/crypto v0.50+ requires it; this version is current
// stable as of April 2026 and is widely deployed. Anyone on Go 1.25+ can
// compile semp-go without upgrading their toolchain.
go 1.25.0

// Additional dependencies anticipated by future milestones (added when the
// corresponding package transitions from stub to functional implementation):
//
//   - github.com/oklog/ulid/v2          (ULIDs for postmark.id, session_id)

require (
	github.com/cloudflare/circl v1.6.3
	github.com/coder/websocket v1.8.14
	golang.org/x/crypto v0.50.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
)
