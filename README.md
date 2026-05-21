# semp-go

The Go reference implementation of the [Sealed Envelope Messaging Protocol (SEMP)](https://github.com/semp-dev/semp-spec).

```
go get semp.dev/semp-go@latest
```

## What is SEMP?

SEMP is an end-to-end encrypted messaging protocol designed for privacy, federation, and post-quantum forward secrecy. Messages are sealed with per-envelope keys so the server reads routing metadata only -- message content is never exposed to any server in transit or at rest.

Key properties:

- **End-to-end encrypted** -- brief (routing metadata) is readable only by the recipient server and client; enclosure (message body) is readable only by the recipient client.
- **Federated** -- any domain can run a SEMP server. Cross-domain delivery uses authenticated federation handshakes with full cryptographic binding.
- **Post-quantum ready** -- the `pq-kyber768-x25519` hybrid suite protects session keys against harvest-now-decrypt-later attacks from future quantum adversaries.
- **Observable reputation** -- domain trust is earned through behavior that other servers can witness. Signed observations are published and independently verifiable.

## Status

**Tracking SEMP spec 0.2.0-draft.** The library implements the full CLIENT + SERVER + CRYPTO protocol layer of the spec, with reference in-memory implementations of every persistence interface. The library is intentionally protocol-only: it ships the wire-format primitives, state machines, and signing / verification helpers, and leaves runtime concerns (HTTP listener mounts, session fan-out, durable storage, demo binaries) to the consuming application or to `semp-reference-server` / `semp-reference-client`.

What's outside the library's scope:

- **Server runtime**: HTTP listener wiring, session demux, fan-out registry. Use `session.Dispatch` and the per-type handlers below to compose your own.
- **Client-side application flows** that belong in `semp-reference-client`: restore-flow orchestration, full identity-rotation cascade driver, enrollment local-pairing.
- **Spec-deferred** items: §3.2 §5.2 delegated forwarding mechanism, §3.5 streaming AEAD modes (both deferred to future spec revisions).
- **Durable storage backends** behind the provided `Store` / `BundleStore` / `LockoutRegistry` / `RateLimitCounter` / `BlockListLookup` interfaces. The library ships in-memory reference impls for every one of them; production deployments MUST plug their own.

See [SPEC-GAP.md](SPEC-GAP.md) for the per-cluster catch-up status.

| Metric | Value |
|---|---|
| Test packages | 24, all passing under `-race` |
| Fuzz targets | 9 (envelope, canonical x2, brief, handshake x3, h2 SSE x2) |
| External deps | 3 (`cloudflare/circl`, `coder/websocket`, `quic-go/quic-go`) |
| Go version | 1.25+ |

## Quick Start

### Server: handshake + dispatch

The library does not own the HTTP listener. Mount whatever framework you use, hand each accepted connection a `transport.Conn`, run the handshake state machine, then enter the post-handshake message loop with `session.Dispatch`:

```go
import (
    "context"

    "semp.dev/semp-go/handshake"
    "semp.dev/semp-go/session"
    "semp.dev/semp-go/transport"
)

// per accepted connection (your framework wraps this in a goroutine):
func serveSession(ctx context.Context, conn transport.Conn) {
    defer conn.Close()

    srv := handshake.NewServer(handshake.ServerConfig{
        Suite:            crypto.SuitePQ,
        Store:            myKeyStore(),
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

    err = session.Dispatch(ctx, conn, session.DispatchHandlers{
        OnEnvelope: func(ctx context.Context, raw []byte) error { return handleEnvelope(ctx, sess, raw) },
        OnFetch:    func(ctx context.Context, raw []byte) error { return handleFetch(ctx, sess, raw) },
        OnRekey:    func(ctx context.Context, raw []byte) error { return handleRekey(ctx, sess, raw) },
        OnKeys:     func(ctx context.Context, raw []byte) error { return handleKeys(ctx, sess, raw) },
    })
    _ = err
}
```

The per-type handlers compose primitives the library already exposes (`envelope.Decode` + `envelope.Verify`, `keys.HandleRequest`, `session.Rekeyer`, etc.). For cross-domain forwarding, drive a `delivery.Forwarder` from inside `OnEnvelope`.

### Client -- Send

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

### Client -- Receive

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
| `keys/memstore` | -- | In-memory key store for tests and demos (NOT for production) |
| `brief` | ENVELOPE.md §5, CLIENT.md §3.5 | Address type with validation, BCC materialization, brief struct |
| `enclosure` | ENVELOPE.md §6 | Message body, attachments with SHA-256/SHA-512 integrity verification |
| `seal` | ENVELOPE.md §4 | Cryptographic seal: signature, session MAC, per-recipient key wrapping |
| `envelope` | ENVELOPE.md, MIME.md | Envelope compose/encode/decode, sign, verify, brief/enclosure decrypt |
| `session` | SESSION.md | Session state, key lifecycle, in-session rekeying (SEMP_REKEY) |
| `handshake` | HANDSHAKE.md | Client and federation handshake state machines, generic challenge framework, PoW solver/verifier, capability negotiation |
| `transport` | TRANSPORT.md §2-§5 | Transport interface, sequential fallback with per-domain cache, length-prefix framer |
| `transport/ws` | TRANSPORT.md §4.1 | WebSocket binding (`semp.v1` subprotocol) |
| `transport/h2` | TRANSPORT.md §4.2 | HTTP/2 binding with persistent Conn adapter and SSE session stream for server-push |
| `transport/quic` | TRANSPORT.md §4.3 | QUIC / HTTP/3 binding via `quic-go` |
| `discovery` | DISCOVERY.md | DNS SRV/TXT discovery, well-known URI fetch, partition resolution (alpha/hash/lookup), signed responses, caching |
| `reputation` | REPUTATION.md | Observation store + scoring, signed trust gossip (sign / verify / fetch primitives plus `ObservationSource` interface), PoW challenge issuance + ledger, signed-disclosure-authorization primitives, domain age interface |
| `delivery` | DELIVERY.md | 9-step delivery pipeline, block list with scope/precedence, signed delivery receipts + envelope-binding, user-policy state machine, retry / cancellation / queue state, staged-delivery runner, scheduler, recipient policy hook, federation `Forwarder` (cross-domain re-sign + cached session + auto-rekey) |
| `closure` | CLOSURE.md | `SEMP_ACCOUNT_CLOSURE` request/cancel records, finalization driver running the §4.2 nine atomic effects, closure persistence Store, recipient-policy adapter for §5 ingress |
| `migration` | MIGRATION.md | `SEMP_MIGRATION` four-signature chained record, cooperative `BuildSubmission` + `AcceptSubmission` flow, `LockoutRegistry`, §5.3 migration_notice rejection, third-party policy hooks, in-memory `PublicationStore` |
| `recovery` | RECOVERY.md | `SEMP_BACKUP_BUNDLE` schema + Argon2id KDF + XChaCha20-Poly1305 payload + HKDF recovery sign-key, Shamir GF(256) split + Lagrange reconstruction, successor record + Shamir manifest + share record signing, `BundleStore`, contributor-pubkey directory cross-check |
| `transparency` | TRANSPARENCY.md | `SEMP_TRANSPARENCY_LEAF` log entries, `SignedTreeHead` issuance + verification, RFC 6962 inclusion + consistency proof generation and verification, append-only `Log` state machine |
| `largeattachment` | ATTACHMENTS.md | `semp.dev/large-attachment` extension types, HKDF-derived per-item keys, AEAD encrypt/decrypt round-trip, ciphertext-hash verification, ULID id generator, ciphertext `Store` interface, enclosure-extension read/write helpers |
| `extensions` | EXTENSIONS.md | Extension entry/map types, key validation (namespace rules), per-layer size limits, default registry from §9 candidate list |
| `clockskew` | CONFORMANCE.md §9.3 | Tiered clock-skew tolerance helpers (`Default`, `Strict`) shared across handshake, delivery, session, keys |
| `canonical` | ENVELOPE.md §4.3 | Canonical JSON serializer used by every signature and MAC computation |
| `session` (Dispatch) | -- | Post-handshake message-loop primitive: reads frames off any `MessageStream`, peeks the outer `type`, fans out to caller-supplied per-type handlers |
| `test` | VECTORS.md | Cross-language vectors runner + integration tests (envelope round-trip, handshake baseline + PQ, rekey, account-recovery bundle round-trip) |

## What You Provide for Production

The library implements the entire SEMP protocol layer. To build a production server or client, you provide the storage and operational backends:

| Interface | What you implement | Why the library doesn't include it |
|---|---|---|
| `keys.Store` / `keys.PrivateStore` | Database-backed key storage with encrypted-at-rest private keys | Storage backends are deployment-specific (PostgreSQL, SQLite, HSM, cloud KMS) |
| `delivery.InboxStore` | Durable message queue with retention policies | `delivery.Inbox` is an in-memory FIFO suitable only for demos |
| `delivery.BlockListLookup` | Per-user block list storage | Block lists are stored encrypted at rest; the storage format is operator-specific |
| `handshake.Policy` | Rate limiting, challenge gating, session TTL, permissions | Policy decisions are operator-specific |
| `reputation.WHOIS` | Domain registration age lookup | No free, reliable WHOIS library exists; the interface is intentionally pluggable |
| HTTP listener / framework wiring | Mounting the SEMP transport endpoints (`/v1/ws`, `/v1/handshake`, `/v1/envelope`, `/v1/session/{id}`, etc.) into your HTTP framework, dispatching to per-session goroutines | Server-side wiring is application-layer; the library exposes the protocol primitives (`session.Dispatch`, handshake state machines, envelope verify / sign) for you to compose |
| TLS certificates | Real certificates for the underlying transport listeners | The transport packages expose an `AllowInsecure` config flag for local testing only |

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
go test ./...                           # every package passes
go test -fuzz=FuzzEnvelopeDecode ./envelope/...  # fuzz the envelope parser
go test -race ./...                     # no data races
```

## Dependencies

| Module | Version | Used by |
|---|---|---|
| `github.com/cloudflare/circl` | v1.6.3 | `crypto` -- Kyber768 KEM for the post-quantum hybrid suite |
| `github.com/coder/websocket` | v1.8.14 | `transport/ws` -- WebSocket binding |
| `github.com/quic-go/quic-go` | v0.59.0 | `transport/quic` -- QUIC / HTTP/3 binding |
| `golang.org/x/crypto` | v0.50.0 | `crypto` -- ChaCha20-Poly1305, X25519, HKDF |

## Versioning

The library follows semver with an explicit pre-1.0 contract that mirrors SEMP itself being draft:

- `v0.x.y` -- pre-1.0. API and wire-format stability are best-effort within a minor version. Minor bumps (`0.3 -> 0.4`) accompany meaningful feature additions or any signature breakage; patch bumps are bug-fix-only.
- `v1.0.0` will ship after the SEMP spec reaches `1.0.0` and the API has stabilized for at least one minor cycle.

The library's version is independent of the SEMP spec version it implements; the [SPEC-GAP.md](SPEC-GAP.md) header records which spec commit each release tracks.

`go get semp.dev/semp-go@latest` resolves to the most recent tag. Pin a specific version (`semp.dev/semp-go@v0.4.0`) for reproducibility.

## License

Code is licensed under the [MIT License](LICENSE). The SEMP protocol specification is published under CC BY 4.0.
