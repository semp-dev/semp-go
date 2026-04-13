// Command semp-server is the reference SEMP server binary.
//
// In its current form it serves a single hard-coded local domain over a
// plain WebSocket listener and handles three operations:
//
//  1. Run the SEMP client handshake against connected clients on /v1/ws.
//  2. After a successful handshake, run delivery/inboxd.Server.Serve in
//     ModeClient to accept envelope submissions and SEMP_FETCH requests.
//  3. Run the federation responder handshake on /v1/federate for
//     connecting peer servers, then run inboxd in ModeFederation to
//     accept forwarded envelopes and route them into local inboxes.
//
// Cross-domain forwarding: when a client submits an envelope addressed
// to a user on a remote domain that matches a -peer entry, the server
// opens a federation session to the peer (lazily), re-binds the session
// MAC under the federation K_env_mac, and forwards the envelope. The
// original domain signature is NOT touched — it's the sender-domain
// provenance proof.
//
// Identity and encryption keys are derived deterministically from a
// shared -seed flag (see internal/demoseed) so cmd/semp-cli and peer
// semp-server instances, given the same seed, can interoperate without
// any out-of-band exchange. This is GROSSLY INSECURE and exists ONLY
// so the demo binaries can be a smoke test.
//
// Usage:
//
//	semp-server [-addr :8080] [-domain a.example]
//	            [-users alice@a.example]
//	            [-peer b.example=ws://127.0.0.1:8081/v1/federate]
//	            [-seed semp-demo-do-not-use-in-production]
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/delivery/inboxd"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/internal/demoseed"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/keys/memstore"
	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/ws"
)

type permitAllPolicy struct{}

func (permitAllPolicy) RequireChallenge(_, _ string) *handshake.Challenge { return nil }
func (permitAllPolicy) BlockedDomain(_ string) bool                   { return false }
func (permitAllPolicy) SessionTTL(_ string) int                       { return 300 }
func (permitAllPolicy) Permissions(_ string) []string                 { return []string{"send", "receive"} }

func main() {
	var (
		addr   = flag.String("addr", ":8080", "WebSocket listen address (host:port)")
		domain = flag.String("domain", "example.com", "Server's home domain")
		users  = flag.String("users", "alice@example.com,bob@example.com", "Comma-separated user identities to pre-seed")
		seed   = flag.String("seed", "semp-demo-do-not-use-in-production", "Deterministic seed for demo identity/encryption keys (demo binary only)")
		peers  = flag.String("peers", "", "Comma-separated peer list: domain=endpoint,domain=endpoint (e.g. 'b.example=ws://127.0.0.1:8081/v1/federate')")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "semp-server ", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("starting %s for domain=%s users=%s", semp.ProtocolVersion, *domain, *users)

	suite := crypto.SuiteBaseline
	store := memstore.New()
	inbox := delivery.NewInbox()

	// Domain signing key (Ed25519).
	domainSignPub, domainSignPriv := demoseed.DomainSigning(*seed, *domain)
	domainSignFP := store.PutDomainKey(*domain, domainSignPub)
	logger.Printf("domain signing key fingerprint: %s", domainSignFP)
	logger.Printf("domain signing key (base64): %s", base64.StdEncoding.EncodeToString(domainSignPub))

	// Domain encryption key (X25519). Published in the local store so
	// SEMP_KEYS requests from clients can resolve it.
	domainEncPub, domainEncPriv, err := demoseed.DomainEncryption(*seed, *domain)
	if err != nil {
		logger.Fatalf("derive domain encryption key: %v", err)
	}
	domainEncFP := store.PutDomainEncryptionKey(*domain, domainEncPub)
	logger.Printf("domain encryption key fingerprint: %s", domainEncFP)
	logger.Printf("domain encryption key (base64): %s", base64.StdEncoding.EncodeToString(domainEncPub))

	// Pre-seed every configured user.
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

	// Parse -peers and register each peer in the Forwarder's registry.
	// Entries can be one of three forms:
	//
	//   b.example=ws://host:port/v1/federate   — static endpoint
	//   b.example                              — discovery-resolved endpoint
	//
	// The signing key always comes from the shared -seed for the
	// demo binary; a real deployment would load it from DANE, a
	// pinned list, or the DNS zone.
	peerRegistry := inboxd.NewPeerRegistry()
	for _, entry := range splitNonEmpty(*peers, ",") {
		var peerDomain, peerEndpoint string
		if eq := strings.IndexByte(entry, '='); eq >= 0 {
			peerDomain = strings.TrimSpace(entry[:eq])
			peerEndpoint = strings.TrimSpace(entry[eq+1:])
		} else {
			peerDomain = strings.TrimSpace(entry)
		}
		peerPub, _ := demoseed.DomainSigning(*seed, peerDomain)
		peerRegistry.Put(inboxd.PeerConfig{
			Domain:           peerDomain,
			Endpoint:         peerEndpoint,
			DomainSigningKey: peerPub,
		})
		// Publish the peer's signing key in our local store so our
		// federation responder can verify inbound handshakes.
		store.PutDomainKey(peerDomain, peerPub)
		if peerEndpoint == "" {
			logger.Printf("peer %s → (discovery-resolved) signing key=%s", peerDomain, keys.Compute(peerPub))
		} else {
			logger.Printf("peer %s → %s signing key=%s", peerDomain, peerEndpoint, keys.Compute(peerPub))
		}
	}

	// Forwarder shared across client-mode connections. Its Dial uses
	// the same WebSocket transport the server listens on, and its
	// Resolver uses the default discovery stack (DNS + well-known +
	// MX fallback) for any PeerConfig whose Endpoint is empty.
	wsTransport := ws.NewWithConfig(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	})
	resolver := discovery.NewResolver(discovery.ResolverConfig{
		Cache: discovery.NewMemCache(),
	})
	forwarder := inboxd.NewForwarder(inboxd.ForwarderConfig{
		Suite:                 suite,
		LocalDomain:           *domain,
		LocalDomainKeyID:      domainSignFP,
		LocalDomainPrivateKey: domainSignPriv,
		Peers:                 peerRegistry,
		Dial: func(ctx context.Context, endpoint string) (transport.Conn, error) {
			return wsTransport.Dial(ctx, endpoint)
		},
		Store:    store,
		Resolver: resolver,
		// The demo server splits client and federation traffic
		// across /v1/ws and /v1/federate on the same host, while
		// the well-known URI publishes a single /v1/ws endpoint.
		// Rewrite ws → federate to match the demo server's layout.
		// A production operator whose server handles both paths at
		// the same URL can omit this and use the default.
		FederationEndpointFunc: func(result *discovery.Result) (string, error) {
			ep, err := inboxd.DefaultFederationEndpointFunc(result)
			if err != nil {
				return "", err
			}
			return strings.Replace(ep, "/v1/ws", "/v1/federate", 1), nil
		},
	})
	defer forwarder.Close()

	logger.Printf("(WARNING: keys are derived deterministically from -seed; this is a demo binary only)")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// We build our own http.ServeMux so we can mount two handlers on
	// the same listener: /v1/ws for clients and /v1/federate for
	// peer servers.
	hctx := &handlerCtx{
		Suite:          suite,
		Store:          store,
		Inbox:          inbox,
		Forwarder:      forwarder,
		Domain:         *domain,
		DomainSignFP:   domainSignFP,
		DomainSignPriv: domainSignPriv,
		DomainEncFP:    domainEncFP,
		DomainEncPriv:  domainEncPriv,
		Logger:         logger,
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/ws", ws.NewHandler(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	}, func(conn transport.Conn) {
		go handleClient(ctx, hctx, conn)
	}))
	mux.Handle("/v1/federate", ws.NewHandler(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	}, func(conn transport.Conn) {
		go handleFederation(ctx, hctx, conn)
	}))
	// Publish a well-known capability document so peers using
	// discovery.Resolver can find our federation endpoint without
	// a static -peers entry. The URL we publish for "ws" is the
	// client endpoint; the peer's FederationEndpointFunc is
	// expected to rewrite it to /v1/federate for actual federation
	// traffic (see the rewrite helper set on the Forwarder above).
	mux.HandleFunc(discovery.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		host := r.Host
		_ = json.NewEncoder(w).Encode(discovery.Configuration{
			Type:    "SEMP_CONFIGURATION",
			Version: semp.ProtocolVersion,
			Domain:  *domain,
			Endpoints: discovery.ConfigEndpoints{
				Client:     map[string]string{"ws": "ws://" + host + "/v1/ws"},
				Federation: map[string]string{"ws": "ws://" + host + "/v1/federate"},
				Register:   "http://" + host + "/v1/register",
				Keys:       "http://" + host + "/.well-known/semp/keys/",
				DomainKeys: "http://" + host + "/.well-known/semp/domain-keys",
			},
			Suites: []string{"x25519-chacha20-poly1305"},
			Limits: discovery.ConfigLimits{MaxEnvelopeSize: 25 * 1024 * 1024},
		})
	})
	httpSrv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	// Run the HTTP server in a goroutine so we can handle signals.
	go func() {
		logger.Printf("listening on http://%s (subprotocol %q)", *addr, ws.Subprotocol)
		logger.Printf("  client endpoint:     ws://%s/v1/ws", *addr)
		logger.Printf("  federation endpoint: ws://%s/v1/federate", *addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http serve: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigCh
	logger.Printf("received signal %s, shutting down", s)
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

// handlerCtx bundles the per-server state needed by the handlers.
type handlerCtx struct {
	Suite          crypto.Suite
	Store          *memstore.Store
	Inbox          *delivery.Inbox
	Forwarder      *inboxd.Forwarder
	Domain         string
	DomainSignFP   keys.Fingerprint
	DomainSignPriv []byte
	DomainEncFP    keys.Fingerprint
	DomainEncPriv  []byte
	Logger         *log.Logger
}

// handleClient drives the client-side handshake against one inbound
// connection and then runs inboxd in ModeClient.
func handleClient(ctx context.Context, h *handlerCtx, conn transport.Conn) {
	defer conn.Close()
	h.Logger.Printf("[client %s] new connection", conn.Peer())

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
		h.Logger.Printf("[client %s] handshake failed: %v", conn.Peer(), err)
		return
	}
	h.Logger.Printf("[client %s] handshake ok: session=%s identity=%s ttl=%s",
		conn.Peer(), sess.ID, srv.ClientIdentity(), sess.TTL)

	loop := &inboxd.Server{
		Mode:           inboxd.ModeClient,
		Suite:          h.Suite,
		Store:          h.Store,
		Inbox:          h.Inbox,
		Forwarder:      h.Forwarder,
		LocalDomain:    h.Domain,
		DomainSignFP:   h.DomainSignFP,
		DomainSignPriv: h.DomainSignPriv,
		DomainEncFP:    h.DomainEncFP,
		DomainEncPriv:  h.DomainEncPriv,
		Identity:       srv.ClientIdentity(),
		DeviceKeyID:    srv.ClientDeviceKeyID(),
		EnvMAC:         sess.EnvMAC(),
		Logger:         h.Logger,
	}
	if err := loop.Serve(ctx, conn); err != nil && err != io.EOF {
		h.Logger.Printf("[client %s] inboxd loop ended: %v", conn.Peer(), err)
		return
	}
	h.Logger.Printf("[client %s] connection closed cleanly", conn.Peer())
}

// handleFederation drives the federation responder handshake against
// one inbound peer connection and then runs inboxd in ModeFederation.
func handleFederation(ctx context.Context, h *handlerCtx, conn transport.Conn) {
	defer conn.Close()
	h.Logger.Printf("[federation %s] new connection", conn.Peer())

	resp := handshake.NewResponder(handshake.ResponderConfig{
		Suite:                 h.Suite,
		Store:                 h.Store,
		Verifier:              handshake.TrustingDomainVerifier{}, // demo
		LocalDomain:           h.Domain,
		LocalDomainKeyID:      h.DomainSignFP,
		LocalDomainPrivateKey: h.DomainSignPriv,
		Policy: handshake.FederationPolicy{
			MessageRetention: "7d",
			UserDiscovery:    "allowed",
			RelayAllowed:     true,
		},
		SessionTTL: 3600,
	})
	defer resp.Erase()

	sess, err := handshake.RunResponder(ctx, conn, resp)
	if err != nil {
		h.Logger.Printf("[federation %s] handshake failed: %v", conn.Peer(), err)
		return
	}
	h.Logger.Printf("[federation %s] handshake ok: session=%s peer=%s ttl=%s",
		conn.Peer(), sess.ID, resp.PeerDomain(), sess.TTL)

	loop := &inboxd.Server{
		Mode:          inboxd.ModeFederation,
		Suite:         h.Suite,
		Store:         h.Store,
		Inbox:         h.Inbox,
		LocalDomain:   h.Domain,
		DomainSignFP:  h.DomainSignFP,
		DomainSignPriv: h.DomainSignPriv,
		DomainEncFP:   h.DomainEncFP,
		DomainEncPriv: h.DomainEncPriv,
		Identity:      resp.PeerDomain(),
		EnvMAC:        sess.EnvMAC(),
		Logger:        h.Logger,
	}
	if err := loop.Serve(ctx, conn); err != nil && err != io.EOF {
		h.Logger.Printf("[federation %s] inboxd loop ended: %v", conn.Peer(), err)
		return
	}
	h.Logger.Printf("[federation %s] connection closed cleanly", conn.Peer())
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
