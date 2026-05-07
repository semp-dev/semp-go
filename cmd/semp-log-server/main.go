// Command semp-log-server is the reference operator-runnable SEMP
// transparency log server. It implements the TRANSPARENCY.md §2 log
// surface plus the §3.1/§3.2 inclusion / consistency proof endpoints
// over HTTP.
//
// Routes (under -base, default /v1/log):
//
//	POST <base>/entries                       Append a LogEntry.
//	GET  <base>/entries/<index>               Fetch a LogEntry.
//	GET  <base>/sth                           Fetch a fresh STH.
//	GET  <base>/proof/inclusion?leaf=N&size=M Inclusion proof.
//	GET  <base>/proof/consistency?from=A&to=B Consistency proof.
//
// Append is gated by a shared-bearer token (-append-token) — only the
// owning home server is expected to append. Read paths are open per
// the §2.3 "STH is publicly verifiable" rule.
//
// Persistence is in-memory in this reference binary. Production
// deployments wrap a durable backend by extending the Log struct
// with a persistent Store interface; for now operators that need
// durability run their own integration on top of the transparency
// package's primitives.
//
// Domain signing key + key id are derived deterministically from a
// -seed flag (see internal/demoseed) so the binary can interoperate
// with the demo semp-server / semp-cli without out-of-band key
// exchange. This is for smoke-test use only; production deployments
// load real domain keys from an HSM or operator-managed key store.
//
// Usage:
//
//	semp-log-server [-addr :8090] [-base /v1/log] [-seed demo]
//	                [-append-token shared-secret]
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/internal/demoseed"
	"semp.dev/semp-go/transparency"
)

func main() {
	addr := flag.String("addr", ":8090", "HTTP listen address")
	base := flag.String("base", "/v1/log", "URL base path for log routes")
	seed := flag.String("seed", "", "demo seed for deterministic domain signing key (REQUIRED for smoke tests; load from HSM in prod)")
	appendToken := flag.String("append-token", "", "shared bearer token for POST /entries (REQUIRED)")
	flag.Parse()

	if *seed == "" {
		log.Fatalf("semp-log-server: -seed is required")
	}
	if *appendToken == "" {
		log.Fatalf("semp-log-server: -append-token is required")
	}

	domainPub, domainPriv := demoseed.DomainSigning(*seed, "log."+(*seed))
	// Use a stable fingerprint of the public key as the key id.
	hash := sha256.Sum256(domainPub)
	domainKeyID := fmt.Sprintf("log-%x", hash[:8])
	log.Printf("semp-log-server: domain key fingerprint = %s", domainKeyID)

	tlog, err := transparency.NewLog(transparency.LogConfig{
		Suite:       crypto.SuiteBaseline,
		DomainKeyID: domainKeyID,
		DomainPriv:  []byte(domainPriv),
	})
	if err != nil {
		log.Fatalf("semp-log-server: NewLog: %v", err)
	}

	handler, err := transparency.LogHandler(transparency.LogHandlerConfig{
		Log:      tlog,
		BasePath: *base,
		AppendAuth: bearerTokenAuth(*appendToken),
	})
	if err != nil {
		log.Fatalf("semp-log-server: LogHandler: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(*base+"/", handler)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Printf("semp-log-server: listening on %s, base path %s", *addr, *base)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("semp-log-server: listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("semp-log-server: shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("semp-log-server: shutdown: %v", err)
	}
}

// bearerTokenAuth returns a constant-time bearer-token check. Returns
// (true, nil) on a match; (false, nil) otherwise.
func bearerTokenAuth(want string) func(*http.Request) (bool, error) {
	return func(r *http.Request) (bool, error) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" || want == "" {
			return false, nil
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return false, nil
		}
		return true, nil
	}
}

