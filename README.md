# semp-go

The Go reference implementation of the [Sealed Envelope Messaging Protocol (SEMP)](https://github.com/semp-dev/semp-spec).

```
go get semp.dev/semp-go@latest
```

## What is SEMP?

SEMP is an end-to-end encrypted messaging protocol designed for privacy, federation, and post-quantum forward secrecy. Messages are sealed with per-envelope keys so the server reads routing metadata only — message content is never exposed to any server in transit or at rest.

Key properties:

- **End-to-end encrypted** — brief (routing metadata) is readable only by the recipient server and client; enclosure (message body) is readable only by the recipient client.
- **Federated** — any domain can run a SEMP server. Cross-domain delivery uses authenticated federation handshakes with full cryptographic binding.
- **Post-quantum ready** — the `pq-kyber768-x25519` hybrid suite protects session keys against harvest-now-decrypt-later attacks from future quantum adversaries.
- **Observable reputation** — domain trust is earned through observed behavior, not self-reported claims. Signed observations are published and independently verifiable.

## Status

**Spec-complete reference implementation.** Every protocol area in the SEMP specification has a working, tested Go implementation. Zero stubs remain. The library is suitable for building production clients and servers when paired with a persistent key store and message storage backend.

| Metric | Value |
|---|---|
| Test packages | 24, all passing |
| Fuzz targets | 9 (envelope, canonical, brief, h2 SSE, handshake PoW) |
| External deps | 3 (`cloudflare/circl`, `coder/websocket`, `quic-go/quic-go`) |
| Go version | 1.25+ |

## Quick Start

### Server

```go
package main

import (
    "context"
    "net/http"

    "semp.dev/semp-go/crypto"
    "semp.dev/semp-go/delivery"
    "semp.dev/semp-go/delivery/inboxd"
    "semp.dev/semp-go/handshake"
    "semp.dev/semp-go/transport"
    "semp.dev/semp-go/transport/ws"
)

func main() {
    suite := crypto.SuitePQ // post-quantum hybrid by default
    store := myKeyStore()   // your keys.Store implementation
    inbox := delivery.NewInbox()

    mux := http.NewServeMux()
    mux.Handle("/v1/ws", ws.NewHandler(ws.Config{}, func(conn transport.Conn) {
        defer conn.Close()
        ctx := context.Background()

        srv := handshake.NewServer(handshake.ServerConfig{
            Suite:            suite,
            Store:            store,
            Policy:           myPolicy(),
            Domain:           "example.com",
            DomainKeyID:      domainKeyFP,
            DomainPrivateKey: domainPriv,
        })
        defer srv.Erase()

        sess, err := handshake.RunServer(ctx, conn, srv)
        if err != nil {
            return
        }

        loop := &inboxd.Server{
            Suite:          suite,
            Store:          store,
            Inbox:          inbox,
            LocalDomain:    "example.com",
            DomainSignFP:   domainKeyFP,
            DomainSignPriv: domainPriv,
            DomainEncFP:    domainEncFP,
            DomainEncPriv:  domainEncPriv,
            Identity:       srv.ClientIdentity(),
            Session:        sess,
        }
        loop.Serve(ctx, conn)
    }))

    http.ListenAndServe(":8080", mux)
}
```

### Client — Send

```go
// After establishing a session via handshake.RunClient...

env, _ := envelope.Compose(&envelope.ComposeInput{
    Suite: crypto.SuitePQ,
    Postmark: envelope.Postmark{
        ID:         "01JPOSTMARK...",
        SessionID:  sess.ID,
        FromDomain: "sender.example",
        ToDomain:   "recipient.example",
        Expires:    time.Now().Add(time.Hour),
    },
    Brief: brief.Brief{
        MessageID: "01JMESSAGE...",
        From:      "alice@sender.example",
        To:        []brief.Address{"bob@recipient.example"},
        SentAt:    time.Now().UTC(),
    },
    Enclosure: enclosure.Enclosure{
        Subject:     "Hello",
        ContentType: "text/plain",
        Body:        enclosure.Body{"text/plain": "Hi Bob!"},
    },
    BriefRecipients:     recipientKeys,
    EnclosureRecipients: recipientKeys,
})
wire, _ := envelope.Encode(env)
conn.Send(ctx, wire)
// Read and parse the SubmissionResponse...
```

### Client — Receive

```go
// After establishing a session...

// Send SEMP_FETCH request
req, _ := json.Marshal(delivery.NewFetchRequest())
conn.Send(ctx, req)

// Read the FetchResponse
respRaw, _ := conn.Recv(ctx)
var resp delivery.FetchResponse
json.Unmarshal(respRaw, &resp)

// Decrypt each envelope
for _, b64 := range resp.Envelopes {
    raw, _ := base64.StdEncoding.DecodeString(b64)
    env, _ := envelope.Decode(raw)

    bf, _ := envelope.OpenBriefAny(env, suite, myKeyCandidates)
    enc, _ := envelope.OpenEnclosureAny(env, suite, myKeyCandidates)

    fmt.Printf("From: %s\nSubject: %s\n%s\n",
        bf.From, enc.Subject, enc.Body["text/plain"])
}
```

## Package Map

| Package | Spec Reference | Role |
|---|---|---|
| `semp.dev/semp-go` (root) | ERRORS.md, DELIVERY.md §1 | Protocol version, reason codes, acknowledgment types, `Error` type |
| `crypto` | ENVELOPE.md §7.3, SESSION.md §2.1, §4.1 | Algorithm suites (`x25519-chacha20-poly1305`, `pq-kyber768-x25519`), X25519+Kyber768 hybrid KEM, AEAD, KDF, MAC, Ed25519 signing |
| `keys` | KEY.md | Key records, fingerprints, revocation publication + fetch + cache, key rotation driver, scoped device certificates, store interface |
| `keys/memstore` | — | In-memory key store for tests and demos (NOT for production) |
| `brief` | ENVELOPE.md §5, CLIENT.md §3.5 | Address type with validation, BCC materialization, brief struct |
| `enclosure` | ENVELOPE.md §6 | Message body, attachments with SHA-256/SHA-512 integrity verification |
| `seal` | ENVELOPE.md §4 | Cryptographic seal: signature, session MAC, per-recipient key wrapping |
| `envelope` | ENVELOPE.md, MIME.md | Envelope compose/encode/decode, sign, verify, brief/enclosure decrypt |
| `session` | SESSION.md | Session state, key lifecycle, in-session rekeying (SEMP_REKEY) |
| `handshake` | HANDSHAKE.md | Client and federation handshake state machines, generic challenge framework, PoW solver/verifier, capability negotiation |
| `transport` | TRANSPORT.md §2–§5 | Transport interface, sequential fallback with per-domain cache, length-prefix framer |
| `transport/ws` | TRANSPORT.md §4.1 | WebSocket binding (`semp.v1` subprotocol) |
| `transport/h2` | TRANSPORT.md §4.2 | HTTP/2 binding with persistent Conn adapter and SSE session stream for server-push |
| `transport/quic` | TRANSPORT.md §4.3 | QUIC / HTTP/3 binding via `quic-go` |
| `discovery` | DISCOVERY.md | DNS SRV/TXT discovery, well-known URI fetch, partition resolution (alpha/hash/lookup), signed responses, caching |
| `reputation` | REPUTATION.md | Observation store + scoring, signed trust gossip publication + fetch, PoW challenge issuance + ledger, abuse report handler with disclosure authorization, domain age interface |
| `delivery` | DELIVERY.md | 9-step delivery pipeline, block list with scope/precedence, block list sync signing, recipient status visibility, internal route types |
| `delivery/inboxd` | — | Post-handshake server loop: envelope submission (client + federation), SEMP_FETCH, SEMP_KEYS, SEMP_REKEY dispatch |
| `extensions` | EXTENSIONS.md | Extension entry/map types, key validation (namespace rules), per-layer size limits, default registry from §9 candidate list |
| `internal/canonical` | ENVELOPE.md §4.3 | Canonical JSON serializer used by every signature and MAC computation |
| `cmd/semp-server` | — | Reference server binary (demo — uses seed-derived keys and in-memory inbox) |
| `cmd/semp-cli` | — | Reference client CLI: `handshake`, `send`, `receive` subcommands |
| `test` | VECTORS.md | Integration tests: envelope round-trip, handshake (baseline + PQ), federation, cross-domain delivery, multi-device, device certs, rekey, PoW challenge |

## What You Provide for Production

The library implements the entire SEMP protocol layer. To build a production server or client, you provide the storage and operational backends:

| Interface | What you implement | Why the library doesn't include it |
|---|---|---|
| `keys.Store` / `keys.PrivateStore` | Database-backed key storage with encrypted-at-rest private keys | Storage backends are deployment-specific (PostgreSQL, SQLite, HSM, cloud KMS) |
| `delivery.InboxStore` | Durable message queue with retention policies | `delivery.Inbox` is an in-memory FIFO suitable only for demos |
| `delivery.BlockListLookup` | Per-user block list storage | Block lists are stored encrypted at rest; the storage format is operator-specific |
| `handshake.Policy` | Rate limiting, challenge gating, session TTL, permissions | Policy decisions are operator-specific |
| `reputation.WHOIS` | Domain registration age lookup | No free, reliable WHOIS library exists; the interface is intentionally pluggable |
| TLS certificates | Real certificates for transport listeners | The demo binaries use `AllowInsecure` for local testing |

## Algorithm Suites

| Suite | Key Agreement | Symmetric | MAC | KDF | Signing | Status |
|---|---|---|---|---|---|---|
| `x25519-chacha20-poly1305` | X25519 | ChaCha20-Poly1305 | HMAC-SHA-256 | HKDF-SHA-512 | Ed25519 | **Required** (baseline) |
| `pq-kyber768-x25519` | Kyber768 + X25519 hybrid | ChaCha20-Poly1305 | HMAC-SHA-256 | HKDF-SHA-512 | Ed25519 | **Recommended** (post-quantum) |

Both suites are fully implemented. `crypto.SuitePQ` is preferred when both peers support it; `crypto.SuiteBaseline` is the mandatory fallback.

## Transport Bindings

All three core transports are implemented and compose through `transport.Fallback`:

| Transport | Package | Protocol | Advantages |
|---|---|---|---|
| WebSocket | `transport/ws` | RFC 6455 over TLS | Persistent bidirectional, traverses nearly all middleboxes |
| HTTP/2 | `transport/h2` | RFC 9113 | Universally supported, SSE session stream for server-push |
| QUIC | `transport/quic` | RFC 9000 + RFC 9114 (HTTP/3) | 0-RTT, no head-of-line blocking, connection migration |

```go
candidates := []transport.Candidate{
    {Transport: quic.New(), Endpoint: "https://semp.example.com/v1"},
    {Transport: ws.New(), Endpoint: "wss://semp.example.com/v1/ws"},
    {Transport: h2.New(), Endpoint: "https://semp.example.com/v1"},
}
conn, err := transport.Fallback(ctx, transport.Order(candidates))
```

## Verification

```sh
go build ./...                          # zero errors
go vet ./...                            # zero findings
go test ./...                           # all 24 packages pass
go test -fuzz=FuzzEnvelopeDecode ./envelope/...  # fuzz the envelope parser
go test -race ./...                     # no data races
```

## Demo Binaries

The `cmd/` directory contains working demo binaries that exercise the full protocol stack in-process:

```sh
# Terminal 1: start the server
go run ./cmd/semp-server -domain example.com -users alice@example.com,bob@example.com

# Terminal 2: send an envelope
go run ./cmd/semp-cli send -url ws://localhost:8080/v1/ws \
    -from alice@example.com -to bob@example.com -body "Hello Bob"

# Terminal 3: receive envelopes
go run ./cmd/semp-cli receive -url ws://localhost:8080/v1/ws \
    -identity bob@example.com
```

These binaries use deterministic seed-derived keys (`internal/demoseed`) and an in-memory inbox. They are **not suitable for production** — they demonstrate the protocol flow and serve as integration tests.

## Dependencies

| Module | Version | Used by |
|---|---|---|
| `github.com/cloudflare/circl` | v1.6.3 | `crypto` — Kyber768 KEM for the post-quantum hybrid suite |
| `github.com/coder/websocket` | v1.8.14 | `transport/ws` — WebSocket binding |
| `github.com/quic-go/quic-go` | v0.59.0 | `transport/quic` — QUIC / HTTP/3 binding |
| `golang.org/x/crypto` | v0.50.0 | `crypto` — ChaCha20-Poly1305, X25519, HKDF |

## License

Code is licensed under the [MIT License](LICENSE). The SEMP protocol specification is published under CC BY 4.0.
