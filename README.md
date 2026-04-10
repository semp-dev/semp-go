# semp-go

A Go implementation of the [Sealed Envelope Messaging Protocol (SEMP)](../semp-spec/README.md).

> **Status: skeleton.** This module currently contains the package layout, the
> primary types from the spec (with JSON tags matching the wire format), and
> stub method signatures. No protocol logic is implemented yet. Every
> unimplemented function carries a `// TODO(SPEC §N)` marker that points back
> at the governing section of the specification.
>
> The skeleton compiles cleanly under `go build ./...` and `go vet ./...` with
> zero external dependencies.

## Module

- Module path: `github.com/semp-dev/semp-go` (placeholder, rename freely).
- Minimum Go version: **1.23** (the `go` directive in `go.mod`).
- Pinned development toolchain: **1.25.0** (the `toolchain` directive).

## Package Map

| Package | Spec | Role |
|---|---|---|
| `github.com/semp-dev/semp-go` (root) | `ERRORS.md`, `DELIVERY.md §1`, `CLIENT.md §6.3`, `DISCOVERY.md §4.6` | Protocol version, reason codes, acknowledgment / submission / discovery enums, `Error` type. |
| `internal/canonical` | `ENVELOPE.md §4.3`, `HANDSHAKE.md §2.5.3` | Canonical JSON serialization used by every signature and MAC computation. |
| `extensions` | `EXTENSIONS.md` | Extension entries, registry, per-layer size limits, criticality semantics. |
| `crypto` | `ENVELOPE.md §7.3`, `HANDSHAKE.md §2.4`, `SESSION.md §2.1`, `VECTORS.md §2` | Algorithm suites (`x25519-chacha20-poly1305` and `pq-kyber768-x25519`), KEM, AEAD, KDF, MAC, signing, secure zeroing. |
| `keys` | `KEY.md` | Key types, key records, fingerprints, revocation, scoped device certificates, key store interface. |
| `brief` | `ENVELOPE.md §5`, `CLIENT.md §3.5` | The encrypted-to-recipient inner header (sender, recipients, threading). |
| `enclosure` | `ENVELOPE.md §6` | The encrypted-to-client message body and attachments. |
| `seal` | `ENVELOPE.md §4` | The cryptographic seal: signature, session MAC, recipient key wraps. |
| `envelope` | `ENVELOPE.md`, `MIME.md` | The top-level envelope, postmark, encode/decode of `application/semp-envelope`. |
| `session` | `SESSION.md` | Session state, key lifecycle, rekey, expiry log, concurrent-session bounds. |
| `handshake` | `HANDSHAKE.md`, `REPUTATION.md §8.3` | Client and federation handshake state machines, PoW, capability negotiation. |
| `transport` | `TRANSPORT.md §2–§5` | Transport interface, profiles (sync/async), framer, fallback ordering. |
| `transport/ws` | `TRANSPORT.md §4.1` | WebSocket binding (`semp.v1` subprotocol). |
| `transport/h2` | `TRANSPORT.md §4.2` | HTTP/2 binding with SSE-based session stream for server-pushed messages. |
| `transport/quic` | `TRANSPORT.md §4.3` | QUIC binding (HTTP/3 over `quic-go`). |
| `discovery` | `DISCOVERY.md` | DNS SRV/TXT and well-known URI discovery, MX fallback, partition resolution, caching. |
| `reputation` | `REPUTATION.md` | Observation records, trust gossip, proof-of-work challenges, abuse reports. |
| `delivery` | `DELIVERY.md` | Delivery pipeline, block list, multi-device sync, recipient status, internal route enforcement. |
| `cmd/semp-server` | — | Reference server binary stub. |
| `cmd/semp-cli` | — | Reference client CLI stub. |
| `test` | `VECTORS.md` | Integration test placeholders, including `vectors_test.go` pre-loaded with the spec test vectors (skipped until implementation lands). |

## Dependency Graph

```
                         semp (root)
                              ▲
                              │
        ┌───────────┬─────────┼─────────┬────────────┬─────────────┐
        │           │         │         │            │             │
  internal/   extensions/   crypto/   keys/      transport/   reputation/
  canonical/                  ▲         ▲            ▲             ▲
        ▲                     │         │            │             │
        │                     └────┬────┘            │             │
        │                          │                 │             │
        │                       session/             │             │
        │                          ▲                 │             │
        │                          │                 │             │
        │                       handshake/ ◄─────────┤             │
        │                          ▲                 │             │
        │                          │                 │             │
        ├─────────┬────────┬──────┴──────┐           │             │
        │         │        │             │           │             │
      brief/  enclosure/  seal/       envelope/      │             │
        ▲         ▲        ▲             ▲           │             │
        └─────────┴────────┴─────────────┘           │             │
                          ▲                          │             │
                          │                          │             │
                     discovery/ ◄────────────────────┤             │
                          ▲                                        │
                          │                                        │
                     delivery/ ◄─────────────────────────────────┘
```

## Anticipated External Dependencies

The skeleton uses only the Go standard library. The following dependencies will
be added as the corresponding packages transition from stub to implementation:

| Dependency | Used by | Purpose |
|---|---|---|
| `github.com/cloudflare/circl` | `crypto` | Kyber768 KEM for the post-quantum hybrid suite. |
| `golang.org/x/crypto` | `crypto` | `chacha20poly1305`, `curve25519`, `hkdf`. |
| `github.com/oklog/ulid/v2` | `envelope`, `session`, `handshake`, `discovery` | ULIDs for `postmark.id`, `session_id`, `message_id`, request IDs. |
| `github.com/coder/websocket` | `transport/ws` | WebSocket binding. |
| `golang.org/x/net` | `transport/h2` | HTTP/2 helpers. |
| `github.com/quic-go/quic-go` | `transport/quic` | QUIC / HTTP/3 binding. |

## Verification

```sh
go build ./...      # must succeed with zero errors
go vet ./...        # must return zero findings
go mod tidy         # no-op on the empty require block today
go test ./test/...  # vector tests are skipped until crypto lands
```

To enumerate all the work waiting in the skeleton:

```sh
grep -rn "TODO(" .
```

Each `TODO(...)` carries the spec section that governs the missing logic.

## License

Code is licensed under the [MIT License](LICENSE). The SEMP protocol
specification documents in `../semp-spec/` are licensed under CC BY 4.0.
