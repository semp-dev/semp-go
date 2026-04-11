package reputation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/internal/canonical"
	"github.com/semp-dev/semp-go/keys"
)

// AbuseReportPath is the well-known path a user client POSTs abuse
// reports to. The home server mounts AbuseReportHandler at this path.
// The path is not defined by REPUTATION.md §3 — the spec only says
// reports flow "to the home server" — so operators are free to mount
// the handler elsewhere. This constant is provided as a sensible
// default.
const AbuseReportPath = "/v1/abuse-report"

// DefaultMaxAbuseReportBytes caps the size of an incoming abuse
// report body. 256 KiB is generous for the metadata-only case and
// still constrains the worst-case sealed-evidence attachment.
const DefaultMaxAbuseReportBytes int64 = 256 * 1024

// -----------------------------------------------------------------------------
// DisclosureAuthorization signing
// -----------------------------------------------------------------------------

// canonicalDisclosureAuthorizationBytes returns the canonical JSON
// form of auth with signature.value elided — same elider pattern as
// the observation signer.
func canonicalDisclosureAuthorizationBytes(auth *DisclosureAuthorization) ([]byte, error) {
	if auth == nil {
		return nil, errors.New("reputation: nil disclosure authorization")
	}
	return canonical.MarshalWithElision(auth, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("reputation: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("reputation: disclosure authorization has no signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignDisclosureAuthorization computes an Ed25519 signature over the
// canonical form of auth and populates auth.Signature. The user's
// own identity private key is used — this is the proof REPUTATION.md
// §3.7 requires before decrypted content can be included in abuse
// evidence.
func SignDisclosureAuthorization(signer crypto.Signer, privKey []byte, userKeyID keys.Fingerprint, auth *DisclosureAuthorization) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if auth == nil {
		return errors.New("reputation: nil disclosure authorization")
	}
	if len(privKey) == 0 {
		return errors.New("reputation: empty signing private key")
	}
	if auth.Scope == "" {
		return errors.New("reputation: disclosure authorization missing scope")
	}
	auth.Signature.Algorithm = keys.SignatureAlgorithmEd25519
	auth.Signature.KeyID = userKeyID
	msg, err := canonicalDisclosureAuthorizationBytes(auth)
	if err != nil {
		return fmt.Errorf("reputation: canonical disclosure authorization: %w", err)
	}
	sigBytes, err := signer.Sign(privKey, msg)
	if err != nil {
		return fmt.Errorf("reputation: sign disclosure authorization: %w", err)
	}
	auth.Signature.Value = base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// VerifyDisclosureAuthorization verifies auth.Signature against the
// affected user's published identity key. The handler MUST call this
// before accepting any evidence that includes decrypted content.
func VerifyDisclosureAuthorization(signer crypto.Signer, auth *DisclosureAuthorization, userPub []byte) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if auth == nil {
		return errors.New("reputation: nil disclosure authorization")
	}
	if auth.Signature.Value == "" {
		return errors.New("reputation: disclosure authorization is unsigned")
	}
	if len(userPub) == 0 {
		return errors.New("reputation: empty user public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(auth.Signature.Value)
	if err != nil {
		return fmt.Errorf("reputation: disclosure authorization signature base64: %w", err)
	}
	msg, err := canonicalDisclosureAuthorizationBytes(auth)
	if err != nil {
		return fmt.Errorf("reputation: canonical disclosure authorization: %w", err)
	}
	if err := signer.Verify(userPub, msg, sigBytes); err != nil {
		return fmt.Errorf("reputation: verify disclosure authorization: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Abuse report handler
// -----------------------------------------------------------------------------

// SessionIdentityFunc extracts the authenticated user identity from
// an incoming HTTP request. The handler uses it to confirm that the
// report's `reporter` field matches the authenticated session, per
// REPUTATION.md §3.1 ("Users report to their own home server only.").
//
// Return ("", false) when the request is not authenticated; the
// handler responds with 401.
type SessionIdentityFunc func(r *http.Request) (identity string, ok bool)

// UserKeyLookup resolves an authenticated user's identity public key
// so the handler can verify embedded DisclosureAuthorization
// signatures. Returning (nil, nil) means "unknown user" and causes
// the handler to reject any evidence that references that user.
type UserKeyLookup func(ctx any, user string) ([]byte, error)

// AbuseReportHandlerConfig groups the inputs to
// NewAbuseReportHandler.
type AbuseReportHandlerConfig struct {
	// Store is the observation store that records verified reports.
	// Required — without a store the handler has nowhere to write.
	Store *ObservationStore

	// Signer is the suite signer used to verify DisclosureAuthorization
	// signatures. Required only when the handler will accept evidence
	// containing decrypted content; callers that only accept metadata
	// evidence MAY leave Signer nil.
	Signer crypto.Signer

	// UserKeys resolves identity public keys for embedded
	// DisclosureAuthorization verification. Required only when Signer
	// is non-nil.
	UserKeys UserKeyLookup

	// SessionIdentity extracts the authenticated user identity from
	// the request. Required — unauthenticated abuse reports are
	// rejected with 401. A typical implementation reads a context
	// value set by upstream middleware.
	SessionIdentity SessionIdentityFunc

	// MaxBodyBytes caps the request body size. Zero picks
	// DefaultMaxAbuseReportBytes.
	MaxBodyBytes int64
}

// NewAbuseReportHandler returns an http.Handler that receives
// SEMP_ABUSE_REPORT messages and feeds verified reports into
// cfg.Store via RecordAbuseReport.
//
// Processing steps:
//
//  1. Authenticate the request via SessionIdentity; reject 401 on
//     failure.
//  2. Parse the request body as an AbuseReport.
//  3. Confirm type/version discriminators.
//  4. Confirm the reporter field matches the authenticated identity
//     (rejecting reports filed on behalf of someone else — a user
//     MUST report to their own home server per §3.1).
//  5. For sealed evidence entries that include decrypted content,
//     verify the embedded DisclosureAuthorization signature against
//     the affected user's identity key. Evidence with decrypted
//     content but no (or an invalid) authorization is rejected with
//     400.
//  6. Record the report in the store via
//     RecordAbuseReport(reported_domain, category).
//  7. Return 202 Accepted on success.
//
// The handler accepts POST only; other methods return 405.
func NewAbuseReportHandler(cfg AbuseReportHandlerConfig) http.Handler {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxAbuseReportBytes
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.Store == nil || cfg.SessionIdentity == nil {
			http.Error(w, "abuse report handler misconfigured", http.StatusInternalServerError)
			return
		}
		identity, ok := cfg.SessionIdentity(r)
		if !ok || identity == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		if r.ContentLength > maxBody {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxBody {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		var report AbuseReport
		if err := json.Unmarshal(body, &report); err != nil {
			http.Error(w, "parse report: "+err.Error(), http.StatusBadRequest)
			return
		}
		if report.Type != AbuseReportType {
			http.Error(w, fmt.Sprintf("unexpected type %q, want %q", report.Type, AbuseReportType), http.StatusBadRequest)
			return
		}
		if !strings.EqualFold(report.Reporter, identity) {
			// §3.1 requires users report to their own home server
			// only. A report whose `reporter` field does not match
			// the authenticated session is either a misconfigured
			// client or an impersonation attempt.
			http.Error(w, "reporter does not match authenticated identity", http.StatusForbidden)
			return
		}
		if strings.TrimSpace(report.ReportedDomain) == "" {
			http.Error(w, "report missing reported_domain", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(string(report.Category)) == "" {
			http.Error(w, "report missing category", http.StatusBadRequest)
			return
		}

		// Evidence validation: for sealed_evidence entries that
		// include decrypted content, verify the embedded
		// DisclosureAuthorization before accepting. Metadata
		// evidence passes without a signature check.
		if err := validateEvidence(&report.Evidence, cfg.Signer, cfg.UserKeys, r.Context()); err != nil {
			http.Error(w, "invalid evidence: "+err.Error(), http.StatusBadRequest)
			return
		}

		cfg.Store.RecordAbuseReport(report.ReportedDomain, report.Category)
		w.WriteHeader(http.StatusAccepted)
	})
}

// validateEvidence walks the evidence payload and enforces the
// REPUTATION.md §3.7 rule: decrypted content requires a valid
// DisclosureAuthorization signed by the affected user.
func validateEvidence(ev *Evidence, signer crypto.Signer, userKeys UserKeyLookup, ctx any) error {
	switch ev.Type {
	case "", EvidenceTypeEnvelopeMetadata:
		// Metadata evidence is always acceptable — the postmark +
		// seal evidence can be independently verified by the
		// receiving server from the sender's published domain key,
		// and no user content is disclosed.
		return nil
	case EvidenceTypeSealedEvidence:
		for i, env := range ev.Envelopes {
			discloses := env.DisclosedBrief != nil || env.DisclosedEnclosure != nil
			if !discloses {
				continue
			}
			if env.DisclosureAuthorization == nil {
				return fmt.Errorf("envelope[%d]: decrypted content without disclosure authorization", i)
			}
			auth := env.DisclosureAuthorization
			if env.DisclosedBrief != nil && !auth.AllowsBrief() {
				return fmt.Errorf("envelope[%d]: brief disclosure outside authorized scope %q", i, auth.Scope)
			}
			if env.DisclosedEnclosure != nil && !auth.AllowsEnclosure() {
				return fmt.Errorf("envelope[%d]: enclosure disclosure outside authorized scope %q", i, auth.Scope)
			}
			// If we have a signer and a user key lookup, verify
			// the authorization signature. Callers that run the
			// handler in metadata-only mode may skip this by
			// leaving Signer or UserKeys nil, but they also cannot
			// accept sealed evidence — we check that here.
			if signer == nil || userKeys == nil {
				return fmt.Errorf("envelope[%d]: sealed evidence not accepted (handler lacks signer/user key lookup)", i)
			}
			pub, err := userKeys(ctx, auth.User)
			if err != nil {
				return fmt.Errorf("envelope[%d]: lookup user key for %s: %w", i, auth.User, err)
			}
			if len(pub) == 0 {
				return fmt.Errorf("envelope[%d]: unknown user %s in disclosure authorization", i, auth.User)
			}
			if err := VerifyDisclosureAuthorization(signer, auth, pub); err != nil {
				return fmt.Errorf("envelope[%d]: %w", i, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown evidence type %q", ev.Type)
	}
}
