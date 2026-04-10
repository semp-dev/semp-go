package test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
	"github.com/semp-dev/semp-go/transport"
	"github.com/semp-dev/semp-go/transport/h2"
)

// TestHandshakeOverH2 is the milestone-3ff acceptance test: it drives a
// full four-message SEMP handshake (init → response → confirm →
// accepted) end-to-end over the new HTTP/2 persistent transport.Conn
// adapter. The listener side uses h2.Transport.Listen and runs the
// server state machine via handshake.RunServer. The dialer side uses
// h2.Transport.Dial and runs handshake.RunClient.
//
// Neither handshake.RunClient nor handshake.RunServer knows or cares
// that each Send is a POST round trip — the turn-based persistent
// conn presents them with a plain handshake.MessageStream.
//
// After this test passes, inboxd.Server.Serve (which also takes a
// handshake.MessageStream and alternates Recv/Send for every
// request-response turn) can run over HTTP/2 without modification.
func TestHandshakeOverH2(t *testing.T) {
	suite := crypto.SuiteBaseline
	store := newMemStore()

	// Client identity.
	identityPub, identityPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity keypair: %v", err)
	}
	identityFP := store.putUserKey("alice@example.com", keys.TypeIdentity, identityPub)
	store.putPrivateKey(identityFP, identityPriv)

	// Server domain.
	domainPub, domainPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("domain keypair: %v", err)
	}
	domainFP := store.putDomainKey("example.com", domainPub)

	// Stand up an h2.Transport listener on an ephemeral port.
	tr := h2.NewWithConfig(h2.PersistentConfig{
		Config: h2.Config{AllowInsecure: true},
	})
	lis, err := tr.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("h2 Listen: %v", err)
	}
	defer lis.Close()

	type addrer interface{ Addr() string }
	serverURL := "http://" + lis.(addrer).Addr()

	// Drive the server side in a goroutine: accept one conn, run a
	// handshake against it, and ship the resulting session to the
	// main goroutine via a channel.
	var wg sync.WaitGroup
	serverSessCh := make(chan *session.Session, 1)
	serverErrCh := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := lis.Accept(context.Background())
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		s := handshake.NewServer(handshake.ServerConfig{
			Suite:            suite,
			Store:            store,
			Policy:           permitAllPolicy{},
			Domain:           "example.com",
			DomainKeyID:      domainFP,
			DomainPrivateKey: domainPriv,
		})
		defer s.Erase()
		hsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sess, err := handshake.RunServer(hsCtx, conn, s)
		if err != nil {
			serverErrCh <- err
			return
		}
		serverSessCh <- sess
	}()

	// Drive the client side: dial, run the handshake, receive the
	// session, assert agreement with the server.
	clientConn, err := tr.Dial(context.Background(), serverURL)
	if err != nil {
		t.Fatalf("h2 Dial: %v", err)
	}
	defer clientConn.Close()

	c := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      "alice@example.com",
		IdentityKeyID: identityFP,
		ServerDomain:  "example.com",
	})
	defer c.Erase()
	hsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientSess, err := handshake.RunClient(hsCtx, clientConn, c)
	if err != nil {
		t.Fatalf("handshake.RunClient: %v", err)
	}
	if clientSess.State != session.StateActive {
		t.Errorf("client session state = %v, want Active", clientSess.State)
	}

	// Collect the server session and compare.
	var serverSess *session.Session
	select {
	case serverSess = <-serverSessCh:
	case err := <-serverErrCh:
		t.Fatalf("server side: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server side did not complete handshake")
	}

	if serverSess.State != session.StateActive {
		t.Errorf("server session state = %v, want Active", serverSess.State)
	}
	if clientSess.ID != serverSess.ID {
		t.Errorf("session ID mismatch over h2: client=%s server=%s", clientSess.ID, serverSess.ID)
	}
	if !bytesEqualHelper(clientSess.EnvMAC(), serverSess.EnvMAC()) {
		t.Error("K_env_mac mismatch over h2")
	}
	if serverSess.PeerIdentity != "alice@example.com" {
		t.Errorf("server PeerIdentity = %q, want alice@example.com", serverSess.PeerIdentity)
	}
	wg.Wait()
}

// TestHandshakeOverH2MultipleConcurrentSessions drives three parallel
// handshakes through one h2.Transport listener. Each session should
// land on its own virtual conn keyed by a distinct Semp-Session-Id.
// This pins the session-registry correctness under concurrency.
func TestHandshakeOverH2MultipleConcurrentSessions(t *testing.T) {
	suite := crypto.SuiteBaseline
	store := newMemStore()

	domainPub, domainPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("domain keypair: %v", err)
	}
	domainFP := store.putDomainKey("example.com", domainPub)

	// Register three identity keys up front so three parallel clients
	// can handshake as three different users.
	users := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	clientIDs := make(map[string]keys.Fingerprint, len(users))
	for _, u := range users {
		pub, priv, err := suite.Signer().GenerateKeyPair()
		if err != nil {
			t.Fatalf("%s id keypair: %v", u, err)
		}
		fp := store.putUserKey(u, keys.TypeIdentity, pub)
		store.putPrivateKey(fp, priv)
		clientIDs[u] = fp
	}

	tr := h2.NewWithConfig(h2.PersistentConfig{
		Config: h2.Config{AllowInsecure: true},
	})
	lis, err := tr.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	type addrer interface{ Addr() string }
	serverURL := "http://" + lis.(addrer).Addr()

	// Server: accept N conns, run a handshake on each in its own
	// goroutine, count successes.
	var acceptWG sync.WaitGroup
	serverDone := make(chan struct{})
	var succeeded int
	var succMu sync.Mutex
	go func() {
		defer close(serverDone)
		for i := 0; i < len(users); i++ {
			conn, err := lis.Accept(context.Background())
			if err != nil {
				return
			}
			acceptWG.Add(1)
			go func(c transport.Conn) {
				defer acceptWG.Done()
				defer c.Close()
				s := handshake.NewServer(handshake.ServerConfig{
					Suite:            suite,
					Store:            store,
					Policy:           permitAllPolicy{},
					Domain:           "example.com",
					DomainKeyID:      domainFP,
					DomainPrivateKey: domainPriv,
				})
				defer s.Erase()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if _, err := handshake.RunServer(ctx, c, s); err != nil {
					t.Errorf("server handshake: %v", err)
					return
				}
				succMu.Lock()
				succeeded++
				succMu.Unlock()
			}(conn)
		}
		acceptWG.Wait()
	}()

	// Clients: drive N handshakes in parallel.
	var clientWG sync.WaitGroup
	for _, user := range users {
		clientWG.Add(1)
		go func(u string) {
			defer clientWG.Done()
			conn, err := tr.Dial(context.Background(), serverURL)
			if err != nil {
				t.Errorf("%s Dial: %v", u, err)
				return
			}
			defer conn.Close()
			c := handshake.NewClient(handshake.ClientConfig{
				Suite:         suite,
				Store:         store,
				Identity:      u,
				IdentityKeyID: clientIDs[u],
				ServerDomain:  "example.com",
			})
			defer c.Erase()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := handshake.RunClient(ctx, conn, c); err != nil {
				t.Errorf("%s RunClient: %v", u, err)
			}
		}(user)
	}
	clientWG.Wait()
	<-serverDone

	succMu.Lock()
	defer succMu.Unlock()
	if succeeded != len(users) {
		t.Errorf("server completed %d/%d handshakes", succeeded, len(users))
	}
}
