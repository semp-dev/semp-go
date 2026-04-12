// Command semp-cli is the reference SEMP client CLI.
//
// Subcommands:
//
//	semp-cli handshake -url ... -identity ... -domain ... -server-key ...
//	semp-cli send      -url ... -from ... -to ... -subject ... -body ...
//	semp-cli receive   -url ... -identity ...
//
// All three subcommands derive their identity and encryption keys
// deterministically from a -seed flag (default
// "semp-demo-do-not-use-in-production"), so cmd/semp-server, given the
// matching seed, knows the public halves without any out-of-band
// exchange. THIS IS GROSSLY INSECURE; the demo binaries exist for smoke
// testing only.
//
// Identity key persistence, real key fetching, multi-recipient sends,
// attachments, BCC, and multipart bodies are all left as future work.
package main

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/internal/demoseed"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/keys/memstore"
	"semp.dev/semp-go/seal"
	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/ws"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "handshake":
		exitOn(runHandshake(os.Args[2:]))
	case "send":
		exitOn(runSend(os.Args[2:]))
	case "receive":
		exitOn(runReceive(os.Args[2:]))
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
  send        compose and submit an envelope through a home server
  receive     pull every waiting envelope from your home server inbox
  version     print the protocol version
  help        show this message

Run "semp-cli <subcommand> -h" for subcommand-specific flags.
`, semp.ProtocolVersion)
}

func exitOn(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "semp-cli: %v\n", err)
	os.Exit(1)
}

// =============================================================================
// handshake
// =============================================================================

func runHandshake(args []string) error {
	cfg, err := parseCommonFlags("handshake", args)
	if err != nil {
		return err
	}
	store, identityFP, _, err := buildClientStore(cfg)
	if err != nil {
		return err
	}
	conn, err := dialServer(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         crypto.SuiteBaseline,
		Store:         store,
		Identity:      cfg.identity,
		IdentityKeyID: identityFP,
		ServerDomain:  cfg.domain,
	})
	defer cli.Erase()
	hsCtx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	sess, err := handshake.RunClient(hsCtx, conn, cli)
	if err != nil {
		return fmt.Errorf("run handshake: %w", err)
	}
	fmt.Printf("session_id=%s\n", sess.ID)
	fmt.Printf("ttl=%s\n", sess.TTL)
	fmt.Printf("expires_at=%s\n", sess.ExpiresAt.Format(time.RFC3339))
	return nil
}

// =============================================================================
// send
// =============================================================================

func runSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	url := fs.String("url", "", "Server WebSocket URL")
	from := fs.String("from", "alice@example.com", "Sender address (this CLI authenticates as this user)")
	to := fs.String("to", "bob@example.com", "Recipient address")
	subject := fs.String("subject", "", "Message subject")
	body := fs.String("body", "", "Message body (text/plain)")
	domain := fs.String("domain", "example.com", "Server's domain")
	seed := fs.String("seed", "semp-demo-do-not-use-in-production", "Deterministic key seed (must match the server's -seed)")
	insecure := fs.Bool("insecure", true, "Allow plain ws:// URLs")
	timeout := fs.Duration("timeout", 30*time.Second, "Operation timeout")
	domainKeyB64 := fs.String("server-key", "", "Server signing key in base64 (printed by semp-server at startup)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *to == "" || *body == "" {
		fs.Usage()
		return errors.New("-url, -to, and -body are required")
	}
	if *domainKeyB64 == "" {
		return errors.New("-server-key is required (printed by semp-server at startup)")
	}

	cfg := &commonFlags{
		url:          *url,
		identity:     *from,
		domain:       *domain,
		seed:         *seed,
		insecure:     *insecure,
		timeout:      *timeout,
		serverKeyB64: *domainKeyB64,
	}
	store, identityFP, _, err := buildClientStore(cfg)
	if err != nil {
		return err
	}

	suite := crypto.SuiteBaseline

	// Open a session.
	conn, err := dialServer(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      *from,
		IdentityKeyID: identityFP,
		ServerDomain:  *domain,
	})
	defer cli.Erase()

	hsCtx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	sess, err := handshake.RunClient(hsCtx, conn, cli)
	if err != nil {
		return fmt.Errorf("run handshake: %w", err)
	}
	fmt.Fprintf(os.Stderr, "handshake ok: session=%s\n", sess.ID)

	// Fetch the recipient's keys and both domain encryption keys via
	// SEMP_KEYS instead of deriving them locally. This is the real
	// spec-compliant path: the client asks its home server for the
	// recipient's published keys, and the home server fetches them
	// from the remote domain (via its cached federation session) on
	// the client's behalf. See CLIENT.md §5.4.
	_ = seed // kept as a flag for continuity; no longer used on the send path
	rk, err := fetchRecipientKeys(hsCtx, conn, *to, *from)
	if err != nil {
		return fmt.Errorf("fetch recipient keys: %w", err)
	}

	// Compose the envelope. BriefRecipients includes the sender's
	// home server, the recipient's home server, AND one entry per
	// registered device encryption key. EnclosureRecipients gets one
	// entry per device (no domain entries — the server MUST NOT be
	// able to decrypt the enclosure per ENVELOPE.md §10.5).
	postmarkID, err := newDemoULID()
	if err != nil {
		return err
	}
	messageID, err := newDemoULID()
	if err != nil {
		return err
	}
	bf := brief.Brief{
		MessageID: messageID,
		From:      brief.Address(*from),
		To:        []brief.Address{brief.Address(*to)},
		SentAt:    time.Now().UTC(),
	}
	enc := enclosure.Enclosure{
		Subject:     *subject,
		ContentType: "text/plain",
		Body: enclosure.Body{
			"text/plain": *body,
		},
	}
	briefRecipients := []seal.RecipientKey{
		{Fingerprint: rk.SenderServerEncFP, PublicKey: rk.SenderServerEnc},
		{Fingerprint: rk.RecipientServerEncFP, PublicKey: rk.RecipientServerEnc},
	}
	enclosureRecipients := make([]seal.RecipientKey, 0, len(rk.RecipientDevices))
	for _, dev := range rk.RecipientDevices {
		briefRecipients = append(briefRecipients, seal.RecipientKey{
			Fingerprint: dev.Fingerprint,
			PublicKey:   dev.PublicKey,
		})
		enclosureRecipients = append(enclosureRecipients, seal.RecipientKey{
			Fingerprint: dev.Fingerprint,
			PublicKey:   dev.PublicKey,
		})
	}
	fmt.Fprintf(os.Stderr, "wrapping for %d recipient device(s)\n", len(rk.RecipientDevices))
	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         postmarkID,
			SessionID:  sess.ID,
			FromDomain: domainOf(*from),
			ToDomain:   domainOf(*to),
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief:               bf,
		Enclosure:           enc,
		SenderDomainKeyID:   keys.Fingerprint("server-fills-in"), // server overwrites on Sign
		BriefRecipients:     briefRecipients,
		EnclosureRecipients: enclosureRecipients,
	}
	env, err := envelope.Compose(in)
	if err != nil {
		return fmt.Errorf("compose envelope: %w", err)
	}

	// Transmit the envelope (unsigned). The server fills in
	// seal.signature and seal.session_mac before storing or relaying.
	wire, err := envelope.Encode(env)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}
	if err := conn.Send(hsCtx, wire); err != nil {
		return fmt.Errorf("send envelope: %w", err)
	}

	// Read the server's submission response.
	respRaw, err := conn.Recv(hsCtx)
	if err != nil {
		return fmt.Errorf("recv submission response: %w", err)
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return fmt.Errorf("parse submission response: %w", err)
	}
	if resp.Type != delivery.SubmissionType {
		return fmt.Errorf("unexpected response type %q", resp.Type)
	}
	for _, r := range resp.Results {
		if r.Status == semp.StatusDelivered {
			fmt.Printf("delivered: envelope=%s recipient=%s\n", resp.EnvelopeID, r.Recipient)
		} else {
			fmt.Printf("rejected:  envelope=%s recipient=%s status=%s reason=%s\n",
				resp.EnvelopeID, r.Recipient, r.Status, r.Reason)
		}
	}
	return nil
}

// =============================================================================
// receive
// =============================================================================

func runReceive(args []string) error {
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	url := fs.String("url", "", "Server WebSocket URL")
	identity := fs.String("identity", "alice@example.com", "User identity to authenticate as")
	domain := fs.String("domain", "example.com", "Server's domain")
	seed := fs.String("seed", "semp-demo-do-not-use-in-production", "Deterministic key seed")
	insecure := fs.Bool("insecure", true, "Allow plain ws:// URLs")
	timeout := fs.Duration("timeout", 30*time.Second, "Operation timeout")
	domainKeyB64 := fs.String("server-key", "", "Server signing key in base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" {
		return errors.New("-url is required")
	}
	if *domainKeyB64 == "" {
		return errors.New("-server-key is required")
	}

	cfg := &commonFlags{
		url:          *url,
		identity:     *identity,
		domain:       *domain,
		seed:         *seed,
		insecure:     *insecure,
		timeout:      *timeout,
		serverKeyB64: *domainKeyB64,
	}
	store, identityFP, _, err := buildClientStore(cfg)
	if err != nil {
		return err
	}
	suite := crypto.SuiteBaseline

	// Derive my own encryption keypair so I can unwrap K_brief and
	// K_enclosure on every envelope I fetch. The demo CLI holds a
	// single derived key, but the open path uses OpenBriefAny /
	// OpenEnclosureAny with a candidate list so a future CLI that
	// holds a retired key plus a current key (post-rotation) or
	// multiple device keys can decrypt without code changes.
	myEncPub, myEncPriv, err := demoseed.Encryption(*seed, *identity)
	if err != nil {
		return fmt.Errorf("derive encryption key: %w", err)
	}
	myEncFP := keys.Compute(myEncPub)
	candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: myEncFP, PrivateKey: myEncPriv},
	}

	// Open a session.
	conn, err := dialServer(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      *identity,
		IdentityKeyID: identityFP,
		ServerDomain:  *domain,
	})
	defer cli.Erase()
	hsCtx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	sess, err := handshake.RunClient(hsCtx, conn, cli)
	if err != nil {
		return fmt.Errorf("run handshake: %w", err)
	}
	fmt.Fprintf(os.Stderr, "handshake ok: session=%s\n", sess.ID)

	// SEMP_FETCH.
	req := delivery.NewFetchRequest()
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal fetch request: %w", err)
	}
	if err := conn.Send(hsCtx, reqBytes); err != nil {
		return fmt.Errorf("send fetch request: %w", err)
	}
	respRaw, err := conn.Recv(hsCtx)
	if err != nil {
		return fmt.Errorf("recv fetch response: %w", err)
	}
	var resp delivery.FetchResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return fmt.Errorf("parse fetch response: %w", err)
	}
	if resp.Type != delivery.FetchType {
		return fmt.Errorf("unexpected response type %q", resp.Type)
	}
	fmt.Printf("envelopes=%d\n", len(resp.Envelopes))
	for i, b64 := range resp.Envelopes {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%d] base64 decode failed: %v\n", i, err)
			continue
		}
		env, err := envelope.Decode(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%d] envelope decode failed: %v\n", i, err)
			continue
		}
		bf, err := envelope.OpenBriefAny(env, suite, candidates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%d] open brief failed: %v\n", i, err)
			continue
		}
		enc, err := envelope.OpenEnclosureAny(env, suite, candidates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%d] open enclosure failed: %v\n", i, err)
			continue
		}
		fmt.Printf("--- envelope %d ---\n", i+1)
		fmt.Printf("from:    %s\n", bf.From)
		fmt.Printf("to:      %s\n", joinAddresses(bf.To))
		fmt.Printf("sent_at: %s\n", bf.SentAt.Format(time.RFC3339))
		fmt.Printf("subject: %s\n", enc.Subject)
		if body, ok := enc.Body["text/plain"]; ok {
			fmt.Printf("body:    %s\n", body)
		}
	}
	return nil
}

// =============================================================================
// shared helpers
// =============================================================================

type commonFlags struct {
	url          string
	identity     string
	domain       string
	seed         string
	insecure     bool
	timeout      time.Duration
	serverKeyB64 string
}

func parseCommonFlags(name string, args []string) (*commonFlags, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	url := fs.String("url", "", "Server WebSocket URL")
	identity := fs.String("identity", "alice@example.com", "User identity to authenticate as")
	domain := fs.String("domain", "example.com", "Server's domain")
	seed := fs.String("seed", "semp-demo-do-not-use-in-production", "Deterministic key seed")
	insecure := fs.Bool("insecure", true, "Allow plain ws:// URLs")
	timeout := fs.Duration("timeout", 30*time.Second, "Operation timeout")
	domainKeyB64 := fs.String("server-key", "", "Server signing key in base64")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *url == "" {
		return nil, errors.New("-url is required")
	}
	if *domainKeyB64 == "" {
		return nil, errors.New("-server-key is required")
	}
	return &commonFlags{
		url:          *url,
		identity:     *identity,
		domain:       *domain,
		seed:         *seed,
		insecure:     *insecure,
		timeout:      *timeout,
		serverKeyB64: *domainKeyB64,
	}, nil
}

// buildClientStore wires up an in-memory store seeded with this client's
// identity keypair and the server's signing public key, derived from
// cfg.seed and cfg.identity / cfg.domain.
func buildClientStore(cfg *commonFlags) (*memstore.Store, keys.Fingerprint, ed25519PrivateKey, error) {
	store := memstore.New()

	// Identity keypair (Ed25519, deterministic from seed).
	identityPub, identityPriv := demoseed.Identity(cfg.seed, cfg.identity)
	identityFP := store.PutUserKey(cfg.identity, keys.TypeIdentity, "ed25519", identityPub)
	store.PutPrivateKey(identityFP, identityPriv)

	// Server signing key (provided via -server-key flag).
	serverPub, err := decodeBase64(cfg.serverKeyB64)
	if err != nil {
		return nil, "", nil, fmt.Errorf("parse -server-key: %w", err)
	}
	store.PutDomainKey(cfg.domain, serverPub)

	return store, identityFP, identityPriv, nil
}

// dialServer opens a WebSocket connection to cfg.url with the configured
// timeout and insecure flag.
func dialServer(cfg *commonFlags) (transport.Conn, error) {
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: cfg.insecure})
	dialCtx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, cfg.url)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.url, err)
	}
	fmt.Fprintf(os.Stderr, "connected to %s (subprotocol %s)\n", conn.Peer(), ws.Subprotocol)
	return conn, nil
}

// recipientKeys bundles the key material the CLI needs to compose a
// multi-device envelope: the recipient server's domain encryption
// key (one entry), the sender server's domain encryption key (one
// entry), and EVERY registered device encryption key for the
// recipient (zero or more entries). A multi-device recipient will
// have multiple device keys; the sender wraps K_brief and
// K_enclosure under each one so any of the recipient's devices can
// decrypt.
type recipientKeys struct {
	// RecipientServerEnc is the recipient server's domain encryption
	// key (raw bytes + fingerprint).
	RecipientServerEnc    []byte
	RecipientServerEncFP  keys.Fingerprint
	// SenderServerEnc is the sender's home server's domain
	// encryption key. The sender wraps K_brief under this so the
	// home server can read brief.to for routing.
	SenderServerEnc    []byte
	SenderServerEncFP  keys.Fingerprint
	// RecipientDevices is one entry per registered device
	// encryption key for the recipient address. At least one entry.
	RecipientDevices []deviceKey
}

// deviceKey is a single recipient device's encryption key material.
type deviceKey struct {
	PublicKey   []byte
	Fingerprint keys.Fingerprint
}

// fetchRecipientKeys sends a SEMP_KEYS request asking for both the
// recipient and the sender's own keys. It verifies the response per
// CLIENT.md §3.3 and returns the full multi-device key set so the
// caller can wrap K_brief / K_enclosure under every registered
// recipient device.
func fetchRecipientKeys(ctx context.Context, conn transport.Conn, to, from string) (*recipientKeys, error) {
	fetcher := keys.NewFetcher(conn)
	req := keys.NewRequest(fmt.Sprintf("cli-%d", time.Now().UnixNano()), []string{to, from})
	resp, err := fetcher.FetchKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	// Verify the response before trusting any key material, per
	// CLIENT.md §3.3:
	//
	//   1. Response-level domain signature (origin_signature) must
	//      verify against the domain key published in each result.
	//   2. Per-record domain signatures must verify against the same
	//      domain key.
	//   3. No returned Record may carry a non-nil Revocation.
	//
	// The Verifier performs all three checks. A failure here MUST
	// block envelope composition — a home server that lies about
	// recipient keys could MITM an outbound message, and §3.3 is
	// the trust boundary that prevents that.
	verifier := &keys.Verifier{Suite: crypto.SuiteBaseline}
	if err := verifier.Verify(resp); err != nil {
		return nil, fmt.Errorf("verify SEMP_KEYS response: %w", err)
	}

	var recipResult, senderResult *keys.ResponseResult
	for i := range resp.Results {
		switch resp.Results[i].Address {
		case to:
			recipResult = &resp.Results[i]
		case from:
			senderResult = &resp.Results[i]
		}
	}
	if recipResult == nil || recipResult.Status != keys.StatusFound {
		return nil, fmt.Errorf("keys for %s not found", to)
	}
	if senderResult == nil || senderResult.Status != keys.StatusFound {
		return nil, fmt.Errorf("keys for %s not found", from)
	}

	// Collect EVERY encryption key record for the recipient. Each
	// one corresponds to a registered device; the sender wraps
	// K_brief and K_enclosure under every device so any of them
	// can decrypt.
	devices, err := collectEncryptionKeys(recipResult.UserKeys)
	if err != nil {
		return nil, fmt.Errorf("recipient encryption keys: %w", err)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no encryption keys for %s", to)
	}

	if recipResult.DomainEncKey == nil {
		return nil, fmt.Errorf("no domain encryption key for %s", recipResult.Domain)
	}
	recipDomainEncPub, err := decodeBase64(recipResult.DomainEncKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode recipient domain enc key: %w", err)
	}
	if senderResult.DomainEncKey == nil {
		return nil, fmt.Errorf("no domain encryption key for %s", senderResult.Domain)
	}
	senderDomainEncPub, err := decodeBase64(senderResult.DomainEncKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode sender domain enc key: %w", err)
	}

	return &recipientKeys{
		RecipientServerEnc:   recipDomainEncPub,
		RecipientServerEncFP: recipResult.DomainEncKey.KeyID,
		SenderServerEnc:      senderDomainEncPub,
		SenderServerEncFP:    senderResult.DomainEncKey.KeyID,
		RecipientDevices:     devices,
	}, nil
}

// collectEncryptionKeys filters records to the encryption-key subset
// and decodes each public key. A record with a present Revocation
// would have been caught by the Verifier already; this is a second
// belt-and-suspenders check.
func collectEncryptionKeys(records []*keys.Record) ([]deviceKey, error) {
	out := make([]deviceKey, 0, len(records))
	for _, rec := range records {
		if rec == nil || rec.Type != keys.TypeEncryption {
			continue
		}
		if rec.Revocation != nil {
			continue
		}
		pub, err := decodeBase64(rec.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode encryption key %s: %w", rec.KeyID, err)
		}
		out = append(out, deviceKey{PublicKey: pub, Fingerprint: rec.KeyID})
	}
	return out, nil
}

// decodeBase64 accepts standard or URL-safe base64, with or without
// padding.
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

// domainOf returns the domain part of an address (everything after the
// last '@').
func domainOf(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return ""
	}
	return address[at+1:]
}

// joinAddresses concatenates a list of brief.Address values for display.
func joinAddresses(addrs []brief.Address) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = string(a)
	}
	return strings.Join(parts, ", ")
}

// newDemoULID returns a fresh ULID-shaped string for use as a postmark
// or message ID. We don't pull in github.com/oklog/ulid for one helper;
// timestamp-based randomness is sufficient for the demo.
func newDemoULID() (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	now := time.Now().UnixNano()
	rand := make([]byte, 10)
	if _, err := readRand(rand); err != nil {
		return "", err
	}
	out := make([]byte, 26)
	// 10 chars of timestamp (low-bit interleaved), 16 chars of random.
	for i := 9; i >= 0; i-- {
		out[i] = alphabet[now&0x1f]
		now >>= 5
	}
	for i := 0; i < 16; i++ {
		out[10+i] = alphabet[int(rand[i/2])>>(4*(i%2))&0x1f]
	}
	return string(out), nil
}

// ed25519PrivateKey is a tiny shim that lets buildClientStore return a
// well-typed value without the cli package importing crypto/ed25519
// directly. We just use a []byte alias.
type ed25519PrivateKey = []byte

// readRand fills b with cryptographically random bytes via crypto/rand.
func readRand(b []byte) (int, error) {
	return crand.Read(b)
}
