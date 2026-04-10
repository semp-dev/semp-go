module github.com/semp-dev/semp-go

// The minimum Go language version required to build this module. Anyone with
// Go 1.23 or newer installed can compile semp-go without upgrading their
// toolchain. This is the compatibility floor.
go 1.23

// The Go toolchain that this module is developed and tested against. Any
// invocation that uses an older toolchain than the one named here will
// transparently download this version. This is the compatibility ceiling.
//
// Pairing a low `go` directive with a high `toolchain` directive is the
// idiomatic Go pattern for libraries that want to be widely usable while
// still being built and tested against the latest stable release.
toolchain go1.25.0

// External dependencies are intentionally absent from this skeleton. Each
// stub file uses only the Go standard library so that `go build ./...` and
// `go vet ./...` succeed immediately, with no `go mod tidy` step required.
//
// The dependencies anticipated by the implementation milestones are documented
// in README.md. They will be added to a `require` block when the corresponding
// package transitions from stub to functional implementation:
//
//   - github.com/cloudflare/circl       (Kyber768 KEM, crypto package)
//   - golang.org/x/crypto               (chacha20poly1305, curve25519, hkdf)
//   - github.com/oklog/ulid/v2          (ULIDs for postmark.id, session_id)
//   - github.com/coder/websocket        (transport/ws binding)
//   - golang.org/x/net                  (HTTP/2 helpers, transport/h2 binding)
//   - github.com/quic-go/quic-go        (transport/quic binding)
