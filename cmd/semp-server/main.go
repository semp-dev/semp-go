// Command semp-server is the reference SEMP server binary.
//
// In its current form it serves a single hard-coded local domain over a
// plain WebSocket listener and handles two operations on each accepted
// connection:
//
//  1. Run the SEMP client handshake against the connected client.
//  2. After a successful handshake, run delivery/inboxd.Server.Serve to
//     accept envelope submissions and to fulfill SEMP_FETCH requests
//     from the client's per-user inbox.
//
// Identity and encryption keys are derived deterministically from a
// shared -seed flag (see internal/demoseed) so cmd/semp-cli, given the
// same seed, can interoperate without any out-of-band exchange. This is
// GROSSLY INSECURE and exists ONLY so the demo binaries can be a smoke
// test. Production deployments register each device's keypair through
// the device authorization flow defined in KEY.md §10.
//
// Usage:
//
//	semp-server [-addr :8080] [-domain example.com]
//	            [-users alice@example.com,bob@example.com]
//	            [-seed semp-demo-do-not-use-in-production]
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/delivery"
	"github.com/semp-dev/semp-go/delivery/inboxd"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/internal/demoseed"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/keys/memstore"
	"github.com/semp-dev/semp-go/transport"
	"github.com/semp-dev/semp-go/transport/ws"
)

type permitAllPolicy struct{}

func (permitAllPolicy) RequirePoW(_, _ string) *handshake.PoWRequired { return nil }
func (permitAllPolicy) BlockedDomain(_ string) bool                   { return false }
func (permitAllPolicy) SessionTTL(_ string) int                       { return 300 }
func (permitAllPolicy) Permissions(_ string) []string                 { return []string{"send", "receive"} }

func main() {
	var (
		addr   = flag.String("addr", ":8080", "WebSocket listen address (host:port)")
		domain = flag.String("domain", "example.com", "Server's home domain")
		users  = flag.String("users", "alice@example.com,bob@example.com", "Comma-separated user identities to pre-seed")
		seed   = flag.String("seed", "semp-demo-do-not-use-in-production", "Deterministic seed for demo identity/encryption keys (demo binary only — never use in production)")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "semp-server ", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("starting %s for domain=%s users=%s", semp.ProtocolVersion, *domain, *users)

	suite := crypto.SuiteBaseline
	store := memstore.New()
	inbox := delivery.NewInbox()

	// Domain signing key (Ed25519). Derived deterministically so that
	// cmd/semp-cli, given the same -seed and -domain, can verify
	// envelopes the server signs.
	domainSignPub, domainSignPriv := demoseed.DomainSigning(*seed, *domain)
	domainSignFP := store.PutDomainKey(*domain, domainSignPub)
	logger.Printf("domain signing key fingerprint: %s", domainSignFP)
	logger.Printf("domain signing key (base64): %s", base64.StdEncoding.EncodeToString(domainSignPub))

	// Domain encryption key (X25519). Used by inboxd.Server to unwrap
	// K_brief from inbound envelopes so the server can read brief.to.
	domainEncPub, domainEncPriv, err := demoseed.DomainEncryption(*seed, *domain)
	if err != nil {
		logger.Fatalf("derive domain encryption key: %v", err)
	}
	domainEncFP := keys.Compute(domainEncPub)
	logger.Printf("domain encryption key fingerprint: %s", domainEncFP)
	logger.Printf("domain encryption key (base64): %s", base64.StdEncoding.EncodeToString(domainEncPub))

	// Pre-seed every configured user with both an identity key and an
	// encryption key. The matching client, given the same seed, derives
	// the matching private halves locally.
	for _, u := range splitNonEmpty(*users, ",") {
		identityPub, _ := demoseed.Identity(*seed, u)
		identityFP := store.PutUserKey(u, keys.TypeIdentity, "ed25519", identityPub)

		encPub, _, err := demoseed.Encryption(*seed, u)
		if err != nil {
			logger.Fatalf("derive encryption key for %s: %v", u, err)
		}
		encFP := store.PutUserKey(u, keys.TypeEncryption, "x25519-chacha20-poly1305", encPub)

		logger.Printf("pre-seeded user %s identity=%s encryption=%s", u, identityFP, encFP)
	}

	logger.Printf("(WARNING: keys are derived deterministically from -seed; this is a demo binary only)")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wsTransport := ws.NewWithConfig(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	})
	listener, err := wsTransport.Listen(ctx, *addr)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	if a, ok := listener.(interface{ Addr() string }); ok {
		logger.Printf("listening on http://%s/v1/ws (subprotocol %q)", a.Addr(), ws.Subprotocol)
	} else {
		logger.Printf("listening on %s", *addr)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		logger.Printf("received signal %s, shutting down", s)
		cancel()
	}()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				logger.Printf("accept loop exiting: %v", ctx.Err())
				return
			}
			logger.Printf("accept: %v", err)
			continue
		}
		go handle(ctx, logger, conn, &handlerCtx{
			Suite:          suite,
			Store:          store,
			Inbox:          inbox,
			Domain:         *domain,
			DomainSignFP:   domainSignFP,
			DomainSignPriv: domainSignPriv,
			DomainEncFP:    domainEncFP,
			DomainEncPriv:  domainEncPriv,
		})
	}
}

// handlerCtx bundles the per-server state needed by handle. Pulled into a
// struct so handle's signature stays manageable.
type handlerCtx struct {
	Suite          crypto.Suite
	Store          *memstore.Store
	Inbox          *delivery.Inbox
	Domain         string
	DomainSignFP   keys.Fingerprint
	DomainSignPriv []byte
	DomainEncFP    keys.Fingerprint
	DomainEncPriv  []byte
}

// handle drives the server-side handshake against one inbound connection,
// then runs the inboxd serving loop until the peer disconnects.
func handle(ctx context.Context, logger *log.Logger, conn transport.Conn, h *handlerCtx) {
	defer conn.Close()
	logger.Printf("[%s] new connection", conn.Peer())

	srv := handshake.NewServer(handshake.ServerConfig{
		Suite:            h.Suite,
		Store:            h.Store,
		Policy:           permitAllPolicy{},
		Domain:           h.Domain,
		DomainKeyID:      h.DomainSignFP,
		DomainPrivateKey: h.DomainSignPriv,
	})
	defer srv.Erase()

	sess, err := handshake.RunServer(ctx, conn, srv)
	if err != nil {
		logger.Printf("[%s] handshake failed: %v", conn.Peer(), err)
		return
	}
	logger.Printf("[%s] handshake succeeded: session=%s identity=%s ttl=%s",
		conn.Peer(), sess.ID, srv.ClientIdentity(), sess.TTL)

	loop := &inboxd.Server{
		Suite:          h.Suite,
		Inbox:          h.Inbox,
		LocalDomain:    h.Domain,
		DomainSignFP:   h.DomainSignFP,
		DomainSignPriv: h.DomainSignPriv,
		DomainEncFP:    h.DomainEncFP,
		DomainEncPriv:  h.DomainEncPriv,
		Identity:       srv.ClientIdentity(),
		EnvMAC:         sess.EnvMAC(),
		Logger:         logger,
	}
	if err := loop.Serve(ctx, conn); err != nil && err != io.EOF {
		logger.Printf("[%s] inboxd loop ended: %v", conn.Peer(), err)
		return
	}
	logger.Printf("[%s] connection closed cleanly", conn.Peer())
}

func splitNonEmpty(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
