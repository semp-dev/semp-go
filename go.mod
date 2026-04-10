module github.com/semp-dev/semp-go

// The minimum Go version required to build this module. Bumped to 1.25
// because golang.org/x/crypto v0.50+ requires it; this version is current
// stable as of April 2026 and is widely deployed. Anyone on Go 1.25+ can
// compile semp-go without upgrading their toolchain.
go 1.25.0

// Additional dependencies anticipated by future milestones (added when the
// corresponding package transitions from stub to functional implementation):
//
//   - github.com/cloudflare/circl       (Kyber768 KEM, crypto package)
//   - github.com/oklog/ulid/v2          (ULIDs for postmark.id, session_id)
//   - github.com/coder/websocket        (transport/ws binding)
//   - golang.org/x/net                  (HTTP/2 helpers, transport/h2 binding)
//   - github.com/quic-go/quic-go        (transport/quic binding)

require (
	github.com/coder/websocket v1.8.14
	golang.org/x/crypto v0.50.0
)

require golang.org/x/sys v0.43.0 // indirect
