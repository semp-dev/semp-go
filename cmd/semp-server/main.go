// Command semp-server is the reference SEMP server binary.
//
// In its current form it serves a single hard-coded user identity over a
// plain WebSocket listener and runs the SEMP client handshake against
// every accepted connection. It is intended for local development, demos,
// and as a smoke target for cmd/semp-cli — NOT for production deployment.
//
// Usage:
//
//	semp-server [-addr :8080] [-domain example.com] [-identity alice@example.com]
//
// On startup the server:
//
//  1. Generates a fresh Ed25519 domain keypair (the corresponding public
//     key fingerprint is printed to stderr).
//  2. Generates a fresh Ed25519 identity keypair for the configured user.
//  3. Loads both into an in-memory keys.Store.
//  4. Starts a WebSocket listener at /v1/ws on -addr.
//  5. For each connection, runs handshake.Server via handshake.RunServer
//     and logs the established session ID + client identity.
//
// Connections are dropped after the handshake completes; envelope
// submission is not yet wired into this binary.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/handshake"
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
		addr     = flag.String("addr", ":8080", "WebSocket listen address (host:port)")
		domain   = flag.String("domain", "example.com", "Server's home domain")
		identity = flag.String("identity", "alice@example.com", "Pre-seeded user identity")
		seed     = flag.String("seed", "semp-demo-do-not-use-in-production", "Deterministic seed for the user identity keypair (demo binary only — never use in production)")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "semp-server ", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("starting %s for domain=%s identity=%s", semp.ProtocolVersion, *domain, *identity)

	suite := crypto.SuiteBaseline
	store := memstore.New()

	// Domain keypair.
	domainPub, domainPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		logger.Fatalf("generate domain key: %v", err)
	}
	domainFP := store.PutDomainKey(*domain, domainPub)
	logger.Printf("domain key fingerprint: %s", domainFP)
	logger.Printf("domain key (base64): %s", base64.StdEncoding.EncodeToString(domainPub))
	logger.Printf("(pass the base64 value above to semp-cli via -server-key)")

	// Pre-seeded user identity. We derive the keypair deterministically
	// from (seed || identity) so that cmd/semp-cli — given the same seed
	// and identity — produces the matching private key without any out-of-
	// band exchange. This is GROSSLY INSECURE and exists ONLY so the demo
	// binaries can interoperate as a smoke test. Real deployments register
	// each device's keypair through the device authorization flow defined
	// in KEY.md §10.
	identityPub := deriveDemoIdentity(*seed, *identity)
	identityFP := store.PutUserKey(*identity, keys.TypeIdentity, "ed25519", identityPub)
	logger.Printf("user identity %s fingerprint: %s", *identity, identityFP)
	logger.Printf("(WARNING: identity keys are derived deterministically from -seed; this is a demo binary only)")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Configure the WS listener and start it. We allow plain ws:// for
	// local dev; production deployments would put this behind a TLS
	// reverse proxy or wrap it with an *http.Server using TLSConfig.
	wsTransport := ws.NewWithConfig(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	})
	listener, err := wsTransport.Listen(ctx, *addr)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Print the actual bound address (useful for -addr :0 in tests).
	if a, ok := listener.(interface{ Addr() string }); ok {
		logger.Printf("listening on http://%s/v1/ws (subprotocol %q)", a.Addr(), ws.Subprotocol)
	} else {
		logger.Printf("listening on %s", *addr)
	}

	// Handle SIGINT/SIGTERM gracefully.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		logger.Printf("received signal %s, shutting down", s)
		cancel()
	}()

	// Accept loop.
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
		go handle(ctx, logger, conn, suite, store, domainFP, domainPriv, *domain)
	}
}

// deriveDemoIdentity returns the Ed25519 public half of an identity
// keypair derived deterministically from (seed || ":" || identity).
//
// This function exists ONLY for the cmd/semp-server / cmd/semp-cli demo
// pair; both sides call it with the same arguments to produce matching
// keypairs without any out-of-band exchange. Production code MUST NOT
// derive identity keys from a string, ever.
func deriveDemoIdentity(seed, identity string) ed25519.PublicKey {
	sum := sha256.Sum256([]byte(seed + ":" + identity))
	return ed25519.NewKeyFromSeed(sum[:]).Public().(ed25519.PublicKey)
}

// handle drives the server-side handshake against one inbound connection
// and logs the outcome.
func handle(ctx context.Context, logger *log.Logger, conn transport.Conn, suite crypto.Suite, store *memstore.Store, domainFP keys.Fingerprint, domainPriv []byte, domain string) {
	defer conn.Close()
	logger.Printf("[%s] new connection", conn.Peer())

	srv := handshake.NewServer(handshake.ServerConfig{
		Suite:            suite,
		Store:            store,
		Policy:           permitAllPolicy{},
		Domain:           domain,
		DomainKeyID:      domainFP,
		DomainPrivateKey: domainPriv,
	})
	defer srv.Erase()

	sess, err := handshake.RunServer(ctx, conn, srv)
	if err != nil {
		logger.Printf("[%s] handshake failed: %v", conn.Peer(), err)
		return
	}
	logger.Printf("[%s] handshake succeeded: session=%s identity=%s ttl=%s",
		conn.Peer(), sess.ID, srv.ClientIdentity(), sess.TTL)
	logger.Printf("[%s] closing connection (envelope routing not yet wired into this binary)", conn.Peer())
}
