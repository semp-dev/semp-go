// Command semp-cli is the reference SEMP client CLI.
//
// In its current form it implements a single subcommand, `handshake`,
// which connects to a SEMP server over WebSocket and runs the client
// handshake to completion. Identity keys are minted ephemerally for the
// duration of one invocation — there is no key persistence yet.
//
// Usage:
//
//	semp-cli handshake -url ws://127.0.0.1:8080/v1/ws \
//	                   -identity alice@example.com \
//	                   -domain example.com
//
// On success the established session ID is printed to stdout and the
// process exits 0.
//
// Future subcommands (not yet wired up):
//
//	semp-cli send     <to> [flags]   compose and send an envelope
//	semp-cli receive  [flags]        retrieve waiting envelopes
//	semp-cli keys     <subcommand>   manage device, identity, and encryption keys
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/keys/memstore"
	"github.com/semp-dev/semp-go/transport/ws"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "handshake":
		if err := runHandshake(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "semp-cli handshake: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("semp-cli %s\n", semp.ProtocolVersion)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "semp-cli: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `semp-cli %s

Subcommands:
  handshake   open a SEMP session against a home server
  version     print the protocol version
  help        show this message

Run "semp-cli handshake -h" for handshake-specific flags.
`, semp.ProtocolVersion)
}

func runHandshake(args []string) error {
	fs := flag.NewFlagSet("handshake", flag.ExitOnError)
	url := fs.String("url", "", "Server WebSocket URL (e.g. wss://semp.example.com/v1/ws)")
	identity := fs.String("identity", "alice@example.com", "User identity to authenticate as")
	domain := fs.String("domain", "example.com", "Server's domain (used to look up its public key)")
	timeout := fs.Duration("timeout", 30*time.Second, "Handshake timeout")
	insecure := fs.Bool("insecure", false, "Allow plain ws:// URLs (local dev only)")
	domainKeyHex := fs.String("server-key", "", "Server domain public key in base64 (REQUIRED for real wss:// connections; for local dev with -insecure the server prints its key on startup and you must paste it here)")
	seed := fs.String("seed", "semp-demo-do-not-use-in-production", "Deterministic seed for the identity keypair (must match the server's -seed; demo binary only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" {
		fs.Usage()
		return fmt.Errorf("-url is required")
	}
	if *domainKeyHex == "" {
		return fmt.Errorf("-server-key is required (the server prints its base64 public key at startup)")
	}

	suite := crypto.SuiteBaseline
	store := memstore.New()

	// Derive the identity keypair deterministically from (seed || identity)
	// so the matching cmd/semp-server, started with the same seed, knows
	// our public half without any out-of-band exchange. This is GROSSLY
	// INSECURE and exists ONLY so the demo binaries can interoperate as a
	// smoke test. See KEY.md §10 for the real device authorization flow.
	identityPub, identityPriv := deriveDemoIdentity(*seed, *identity)
	identityFP := store.PutUserKey(*identity, keys.TypeIdentity, "ed25519", identityPub)
	store.PutPrivateKey(identityFP, identityPriv)
	fmt.Fprintf(os.Stderr, "demo identity key fingerprint: %s\n", identityFP)

	// Decode the server's domain public key from the -server-key flag and
	// register it in the store under the configured domain. The handshake
	// Client will look it up to verify message 2's server_signature.
	serverPub, err := decodeBase64(*domainKeyHex)
	if err != nil {
		return fmt.Errorf("parse -server-key: %w", err)
	}
	store.PutDomainKey(*domain, serverPub)

	// Dial the server.
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: *insecure})
	dialCtx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, *url)
	if err != nil {
		return fmt.Errorf("dial %s: %w", *url, err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "connected to %s (subprotocol %s)\n", conn.Peer(), ws.Subprotocol)

	// Run the handshake.
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      *identity,
		IdentityKeyID: identityFP,
		ServerDomain:  *domain,
	})
	defer cli.Erase()

	hsCtx, hsCancel := context.WithTimeout(context.Background(), *timeout)
	defer hsCancel()
	sess, err := handshake.RunClient(hsCtx, conn, cli)
	if err != nil {
		return fmt.Errorf("run handshake: %w", err)
	}
	fmt.Printf("session_id=%s\n", sess.ID)
	fmt.Printf("ttl=%s\n", sess.TTL)
	fmt.Printf("expires_at=%s\n", sess.ExpiresAt.Format(time.RFC3339))
	return nil
}

// deriveDemoIdentity returns the (public, private) Ed25519 keypair derived
// deterministically from (seed || ":" || identity). Both halves are
// returned so the CLI can sign with the private key while registering the
// public key in its in-memory store. This function MUST stay byte-for-byte
// identical to the matching helper in cmd/semp-server/main.go.
//
// PRODUCTION CODE MUST NOT DERIVE IDENTITY KEYS FROM A STRING. EVER.
func deriveDemoIdentity(seed, identity string) (ed25519.PublicKey, ed25519.PrivateKey) {
	sum := sha256.Sum256([]byte(seed + ":" + identity))
	priv := ed25519.NewKeyFromSeed(sum[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// decodeBase64 accepts standard or URL-safe base64, with or without
// padding, so users don't need to guess which form the server printed.
func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not a valid base64 string")
}
