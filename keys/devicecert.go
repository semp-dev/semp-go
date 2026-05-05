package keys

import (
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/brief"
)

// MaxScopeMatcherEntries is the combined cap on the size of `allow`
// plus `deny` in a single scope matcher per KEY.md §10.3.3.1.
const MaxScopeMatcherEntries = 10000

// MaxScopeRateLimitTiers caps the number of rate-limit tiers per
// scope field per KEY.md §10.3.3.3.
const MaxScopeRateLimitTiers = 16

// MaxDeviceCertificateLifetime caps the validity window of a scoped
// device certificate per KEY.md §10.3.8: 365 days.
const MaxDeviceCertificateLifetime = 365 * 24 * time.Hour

// DeviceCertificate is a SEMP_DEVICE_CERTIFICATE binding a delegated
// device's public key to a permission scope and signed by an
// authorizing primary device. The home server enforces the scope on
// every relevant operation by the delegated device per KEY.md
// §10.3.4.
//
// Reference: KEY.md §10.3.
type DeviceCertificate struct {
	// Type is the JSON discriminator; always "SEMP_DEVICE_CERTIFICATE".
	Type string `json:"type"`

	// Version is the certificate format version (semver).
	Version string `json:"version"`

	// DeviceID is the stable identifier of the delegated device. ULID
	// RECOMMENDED.
	DeviceID string `json:"device_id"`

	// DevicePublicKey is the base64-encoded public key of the delegated
	// device.
	DevicePublicKey string `json:"device_public_key"`

	// Account is the full SEMP address the delegated device is bound to.
	Account string `json:"account"`

	// IssuedBy is the device_id of the issuing full-access device.
	IssuedBy string `json:"issued_by"`

	// IssuedAt is the issuance timestamp (ISO 8601 UTC on the wire).
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is the expiry timestamp. Subject to the lifetime
	// bounds in MaxDeviceCertificateLifetime.
	ExpiresAt time.Time `json:"expires_at"`

	// Scope is the permission scope granted to the delegated device.
	Scope Scope `json:"scope"`

	// Signature is the issuer's signature over the canonical
	// certificate bytes (with this field's `value` set to "" during
	// signing).
	Signature PublicationSignature `json:"signature"`
}

// Scope is the permission scope embedded in a device certificate.
// Every field is REQUIRED including its nested rate_limits array
// (which MAY be empty). See KEY.md §10.3.3.
type Scope struct {
	// Send governs which recipients this device may send envelopes to.
	// Uses the matcher shape; delivery_stage MUST be omitted on send.
	Send ScopeMatcher `json:"send"`

	// Receive governs which senders this device may receive envelopes
	// from (matched against brief.from after decryption). Uses the
	// matcher shape; delivery_stage MAY be present.
	Receive ScopeMatcher `json:"receive"`

	// Blocklist governs access to the account's block list.
	Blocklist ScopeResource `json:"blocklist"`

	// Keys governs access to the account's key rotation history and
	// per-device key metadata.
	Keys ScopeResource `json:"keys"`

	// Devices governs access to the account's registered devices and
	// their scoped certificates.
	Devices ScopeResource `json:"devices"`
}

// MatcherMode is the policy mode of a ScopeMatcher per KEY.md
// §10.3.3.1.
type MatcherMode string

// Matcher modes.
const (
	// MatcherModeUnrestricted permits all peers. Allow and Deny MUST
	// be absent or empty.
	MatcherModeUnrestricted MatcherMode = "unrestricted"

	// MatcherModeRestricted permits only peers matching an Allow
	// entry. Allow MUST be non-empty; Deny MUST be absent or empty.
	MatcherModeRestricted MatcherMode = "restricted"

	// MatcherModeDenylist permits all peers except those matching a
	// Deny entry. Deny MUST be non-empty; Allow MUST be absent or
	// empty.
	MatcherModeDenylist MatcherMode = "denylist"

	// MatcherModeNone permits no peers. Allow and Deny MUST be absent
	// or empty.
	MatcherModeNone MatcherMode = "none"
)

// ScopeMatcher is the matcher-shape permission used by Scope.Send and
// Scope.Receive per KEY.md §10.3.3.1.
type ScopeMatcher struct {
	Mode       MatcherMode      `json:"mode"`
	Allow      []ScopeEntry     `json:"allow,omitempty"`
	Deny       []ScopeEntry     `json:"deny,omitempty"`
	RateLimits []RateLimitTier  `json:"rate_limits"`

	// DeliveryStage is the device's position in the staged-delivery
	// ordering per DELIVERY.md §3.2. Present only on Scope.Receive;
	// MUST be omitted on Scope.Send.
	DeliveryStage int `json:"delivery_stage,omitempty"`
}

// EntityType labels a ScopeEntry per DELIVERY.md §5.3.
type EntityType string

// EntityType values.
const (
	EntityTypeUser   EntityType = "user"
	EntityTypeDomain EntityType = "domain"
	EntityTypeServer EntityType = "server"
)

// ScopeEntry is one entry in a matcher's allow or deny list. Entries
// use the same shape as DELIVERY.md §5.3 block entries.
type ScopeEntry struct {
	Type EntityType `json:"type"`

	// Address is set when Type is "user". MUST be a fully-canonical
	// SEMP address per ENVELOPE.md §2.3.
	Address string `json:"address,omitempty"`

	// Domain is set when Type is "domain" or "server". For "domain",
	// matches any SEMP address in that domain. For "server", matches
	// the recipient/sender server identity.
	Domain string `json:"domain,omitempty"`
}

// ScopeResource is the resource-shape permission used by
// Scope.Blocklist, Scope.Keys, and Scope.Devices per KEY.md
// §10.3.3.2.
type ScopeResource struct {
	Read       bool            `json:"read"`
	Write      bool            `json:"write"`
	RateLimits []RateLimitTier `json:"rate_limits"`
}

// RateLimitTier is a single rolling-window rate cap per KEY.md
// §10.3.3.3.
type RateLimitTier struct {
	// PeriodSeconds is the rolling window length. MUST be >= 1.
	PeriodSeconds int `json:"period_seconds"`

	// AmountAllowed is the maximum number of operations permitted
	// within any rolling window of PeriodSeconds. MUST be >= 0.
	// Zero prohibits the operation for the duration of PeriodSeconds.
	AmountAllowed int `json:"amount_allowed"`
}

// AllowsRecipient reports whether s permits sending to the given
// recipient address per KEY.md §10.3.3.1. A recipient is permitted
// when MatcherModeUnrestricted, when MatcherModeRestricted with the
// recipient matching at least one Allow entry, or when
// MatcherModeDenylist with the recipient matching no Deny entry.
//
// AllowsRecipient does NOT evaluate rate limits; the caller applies
// rate-limit tiers separately per §10.3.4.
func (s ScopeMatcher) AllowsRecipient(recipient brief.Address) bool {
	switch s.Mode {
	case MatcherModeUnrestricted:
		return true
	case MatcherModeNone:
		return false
	case MatcherModeRestricted:
		return matchAny(s.Allow, recipient)
	case MatcherModeDenylist:
		return !matchAny(s.Deny, recipient)
	default:
		// Unknown mode fails closed.
		return false
	}
}

// AllowsSender reports whether s permits receiving from the given
// sender address. Same evaluation as AllowsRecipient; the names are
// distinct so call sites read clearly at scope.send vs scope.receive.
func (s ScopeMatcher) AllowsSender(sender brief.Address) bool {
	return s.AllowsRecipient(sender)
}

// matchAny reports whether any entry in entries matches addr per
// the entity-type rules of DELIVERY.md §5.3.
func matchAny(entries []ScopeEntry, addr brief.Address) bool {
	a := brief.Address(string(addr)) // ensure typed for Equal
	for _, e := range entries {
		switch e.Type {
		case EntityTypeUser:
			if e.Address == "" {
				continue
			}
			if a.Equal(brief.Address(e.Address)) {
				return true
			}
		case EntityTypeDomain:
			if e.Domain == "" {
				continue
			}
			if equalDomain(string(a), e.Domain) {
				return true
			}
		case EntityTypeServer:
			// Server entries match a recipient if the address's
			// domain hosts at the same server. Without server-key
			// resolution at this layer we approximate by domain
			// equality; production deployments fold server resolution
			// into the matcher pipeline.
			if e.Domain == "" {
				continue
			}
			if equalDomain(string(a), e.Domain) {
				return true
			}
		}
	}
	return false
}

func equalDomain(addr, domain string) bool {
	at := -1
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '@' {
			at = i
			break
		}
	}
	if at < 0 {
		return false
	}
	return brief.Address(addr[at+1:]) == brief.Address(domain) ||
		// Compare with case folding through brief.Equal applied to a
		// fake "x@domain" form so the IDNA-aware equality runs.
		brief.Address("x@"+addr[at+1:]).Equal(brief.Address("x@" + domain))
}

// Validate reports whether c is structurally well-formed per KEY.md
// §10.3.3 and §10.3.8. Validate does NOT verify the signature; pair
// it with VerifyChain for full validation.
//
// On success returns nil. On failure returns a typed error whose
// message is suitable for embedding in a `reason_code: "scope_invalid"`
// rejection per the spec; the underlying reason code is the caller's
// responsibility to attach.
func (c *DeviceCertificate) Validate() error {
	if c == nil {
		return errors.New("keys: nil device certificate")
	}
	if c.Type != "SEMP_DEVICE_CERTIFICATE" {
		return fmt.Errorf("keys: device certificate type %q, want SEMP_DEVICE_CERTIFICATE", c.Type)
	}
	if c.DeviceID == "" {
		return errors.New("keys: device certificate missing device_id")
	}
	if c.DevicePublicKey == "" {
		return errors.New("keys: device certificate missing device_public_key")
	}
	if c.Account == "" {
		return errors.New("keys: device certificate missing account")
	}
	if c.IssuedBy == "" {
		return errors.New("keys: device certificate missing issued_by")
	}
	if c.IssuedAt.IsZero() {
		return errors.New("keys: device certificate missing issued_at")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("keys: device certificate missing expires_at")
	}
	if !c.ExpiresAt.After(c.IssuedAt) {
		return errors.New("keys: device certificate expires_at MUST be after issued_at")
	}
	if c.ExpiresAt.Sub(c.IssuedAt) > MaxDeviceCertificateLifetime {
		return fmt.Errorf("keys: device certificate lifetime %s exceeds %s cap (KEY.md §10.3.8)",
			c.ExpiresAt.Sub(c.IssuedAt), MaxDeviceCertificateLifetime)
	}
	if err := c.Scope.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate reports whether s is structurally well-formed per KEY.md
// §10.3.3.
func (s Scope) Validate() error {
	if err := s.Send.validate(false); err != nil {
		return fmt.Errorf("scope.send: %w", err)
	}
	if err := s.Receive.validate(true); err != nil {
		return fmt.Errorf("scope.receive: %w", err)
	}
	if err := s.Blocklist.validate(); err != nil {
		return fmt.Errorf("scope.blocklist: %w", err)
	}
	if err := s.Keys.validate(); err != nil {
		return fmt.Errorf("scope.keys: %w", err)
	}
	if err := s.Devices.validate(); err != nil {
		return fmt.Errorf("scope.devices: %w", err)
	}
	return nil
}

func (m ScopeMatcher) validate(allowDeliveryStage bool) error {
	switch m.Mode {
	case MatcherModeUnrestricted, MatcherModeNone:
		if len(m.Allow) > 0 || len(m.Deny) > 0 {
			return fmt.Errorf("matcher mode %q: allow and deny MUST be empty", m.Mode)
		}
	case MatcherModeRestricted:
		if len(m.Allow) == 0 {
			return fmt.Errorf("matcher mode %q: allow MUST be non-empty", m.Mode)
		}
		if len(m.Deny) > 0 {
			return fmt.Errorf("matcher mode %q: deny MUST be empty", m.Mode)
		}
	case MatcherModeDenylist:
		if len(m.Deny) == 0 {
			return fmt.Errorf("matcher mode %q: deny MUST be non-empty", m.Mode)
		}
		if len(m.Allow) > 0 {
			return fmt.Errorf("matcher mode %q: allow MUST be empty", m.Mode)
		}
	default:
		return fmt.Errorf("matcher mode %q is not a valid mode", m.Mode)
	}
	if total := len(m.Allow) + len(m.Deny); total > MaxScopeMatcherEntries {
		return fmt.Errorf("matcher allow+deny size %d exceeds cap %d", total, MaxScopeMatcherEntries)
	}
	for i, e := range m.Allow {
		if err := e.validate(); err != nil {
			return fmt.Errorf("allow[%d]: %w", i, err)
		}
	}
	for i, e := range m.Deny {
		if err := e.validate(); err != nil {
			return fmt.Errorf("deny[%d]: %w", i, err)
		}
	}
	if !allowDeliveryStage && m.DeliveryStage != 0 {
		return errors.New("delivery_stage MUST be omitted on send matcher")
	}
	if allowDeliveryStage && m.DeliveryStage < 0 {
		return fmt.Errorf("delivery_stage %d MUST be >= 1 (or 0 to omit)", m.DeliveryStage)
	}
	if err := validateRateLimits(m.RateLimits); err != nil {
		return err
	}
	return nil
}

func (e ScopeEntry) validate() error {
	switch e.Type {
	case EntityTypeUser:
		if e.Address == "" {
			return errors.New("user entry MUST set address")
		}
	case EntityTypeDomain, EntityTypeServer:
		if e.Domain == "" {
			return fmt.Errorf("%s entry MUST set domain", e.Type)
		}
	default:
		return fmt.Errorf("entry type %q is not a valid entity type", e.Type)
	}
	return nil
}

func (r ScopeResource) validate() error {
	if err := validateRateLimits(r.RateLimits); err != nil {
		return err
	}
	return nil
}

func validateRateLimits(tiers []RateLimitTier) error {
	if len(tiers) > MaxScopeRateLimitTiers {
		return fmt.Errorf("rate_limits has %d tiers, cap is %d", len(tiers), MaxScopeRateLimitTiers)
	}
	for i, t := range tiers {
		if t.PeriodSeconds < 1 {
			return fmt.Errorf("rate_limits[%d]: period_seconds %d MUST be >= 1", i, t.PeriodSeconds)
		}
		if t.AmountAllowed < 0 {
			return fmt.Errorf("rate_limits[%d]: amount_allowed %d MUST be >= 0", i, t.AmountAllowed)
		}
	}
	return nil
}
