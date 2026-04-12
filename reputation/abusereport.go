package reputation

import (
	"time"

	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/keys"
)

// AbuseReportType is the wire-level type discriminator for abuse
// reports (REPUTATION.md §3.2).
const AbuseReportType = "SEMP_ABUSE_REPORT"

// AbuseReportVersion is the SEMP protocol version this implementation
// writes into outgoing abuse reports.
const AbuseReportVersion = "1.0.0"

// AbuseCategory classifies the nature of a reported abuse incident
// (REPUTATION.md §3.4, ERRORS.md §9).
type AbuseCategory string

// Defined abuse categories.
const (
	AbuseSpam          AbuseCategory = "spam"
	AbuseHarassment    AbuseCategory = "harassment"
	AbusePhishing      AbuseCategory = "phishing"
	AbuseMalware       AbuseCategory = "malware"
	AbuseProtocolAbuse AbuseCategory = "protocol_abuse"
	AbuseImpersonation AbuseCategory = "impersonation"
	AbuseOther         AbuseCategory = "other"
)

// KnownAbuseCategory reports whether c is one of the categories
// defined in REPUTATION.md §3.4. Unknown categories are permitted
// for forward compatibility but a handler MAY choose to reject or
// quarantine them.
func KnownAbuseCategory(c AbuseCategory) bool {
	switch c {
	case AbuseSpam, AbuseHarassment, AbusePhishing, AbuseMalware,
		AbuseProtocolAbuse, AbuseImpersonation, AbuseOther:
		return true
	}
	return false
}

// AbuseReport is a SEMP_ABUSE_REPORT message that flows from a user
// (or from a user's home server on the user's behalf) to the user's
// home server. Its JSON layout matches REPUTATION.md §3.2 exactly.
//
// Abuse reports are user → home-server messages sent over an already-
// authenticated session — the handshake identified the reporting user
// so the abuse report itself does not carry its own signature (the
// §3.2 schema has no signature field). The report's evidence may
// include decrypted envelope fragments, in which case an embedded
// DisclosureAuthorization signed by the affected user is required
// per §3.5 + §3.7.
type AbuseReport struct {
	// Type is the wire discriminator. MUST be AbuseReportType.
	Type string `json:"type"`

	// Version is the SEMP protocol version.
	Version string `json:"version"`

	// ID is the unique report identifier. ULID RECOMMENDED.
	ID string `json:"id"`

	// Reporter is the address of the reporting user.
	Reporter string `json:"reporter"`

	// ReportedDomain is the domain of the reported sender.
	ReportedDomain string `json:"reported_domain"`

	// ReportedAddress is the specific address of the reported
	// sender, if known. Present only when the reporter has
	// decrypted the brief and learned the full sender address.
	ReportedAddress string `json:"reported_address,omitempty"`

	// Category classifies the abuse per §3.4.
	Category AbuseCategory `json:"category"`

	// Timestamp is the ISO 8601 UTC time the report was generated.
	Timestamp time.Time `json:"timestamp"`

	// Evidence is the evidence payload per §3.5.
	Evidence Evidence `json:"evidence"`

	// Description is an optional human-readable description.
	Description string `json:"description,omitempty"`

	// Extensions is the application-defined metadata block. Always
	// emitted (even when empty) so canonical bytes are stable.
	Extensions extensions.Map `json:"extensions"`
}

// Evidence is the polymorphic evidence payload carried in
// AbuseReport.Evidence. Its Type field discriminates between
// envelope_metadata and sealed_evidence per REPUTATION.md §3.5.
//
// Fields that don't belong to the current Type are emitted with
// omitempty so unused discriminators don't pollute the wire format.
type Evidence struct {
	// Type is the evidence type: "envelope_metadata" or
	// "sealed_evidence".
	Type string `json:"type"`

	// --- Fields for Type == "envelope_metadata" ---

	// PostmarkIDs is the list of postmark.id values cited as
	// evidence. Populated only for envelope_metadata evidence.
	PostmarkIDs []string `json:"postmark_ids,omitempty"`

	// Count is the number of envelopes observed in the reporting
	// window. Populated only for envelope_metadata evidence.
	Count int `json:"count,omitempty"`

	// Window is an ISO 8601 interval string (e.g.
	// "2025-06-10T19:00:00Z/2025-06-10T20:00:00Z") covering the
	// reporting window. Populated only for envelope_metadata
	// evidence.
	Window string `json:"window,omitempty"`

	// --- Fields for Type == "sealed_evidence" ---

	// Envelopes carries full or partial envelope data (postmark,
	// seal, and optionally disclosed brief / enclosure fragments).
	// Populated only for sealed_evidence.
	Envelopes []SealedEnvelopeEvidence `json:"envelopes,omitempty"`
}

// Evidence types.
const (
	EvidenceTypeEnvelopeMetadata = "envelope_metadata"
	EvidenceTypeSealedEvidence   = "sealed_evidence"
)

// SealedEnvelopeEvidence is one envelope's worth of sealed-evidence
// data per REPUTATION.md §3.5 "Sealed Evidence".
type SealedEnvelopeEvidence struct {
	// Postmark is the verbatim postmark.
	Postmark map[string]any `json:"postmark"`

	// Seal is the verbatim seal.
	Seal map[string]any `json:"seal"`

	// DisclosedBrief, if non-nil, is the decrypted brief content
	// the affected user has authorized for disclosure.
	DisclosedBrief map[string]any `json:"disclosed_brief,omitempty"`

	// DisclosedEnclosure, if non-nil, is the decrypted enclosure
	// content the affected user has authorized for disclosure.
	DisclosedEnclosure map[string]any `json:"disclosed_enclosure,omitempty"`

	// DisclosureAuthorization is the affected user's signed
	// permission to include the decrypted content. REQUIRED when
	// DisclosedBrief or DisclosedEnclosure is non-nil (§3.7 MUST).
	DisclosureAuthorization *DisclosureAuthorization `json:"disclosure_authorization,omitempty"`
}

// DisclosureAuthorization is the affected user's explicit signed
// permission to include decrypted brief or enclosure content as
// evidence in an abuse report (REPUTATION.md §3.5 + §3.7).
type DisclosureAuthorization struct {
	// User is the address of the user authorizing disclosure.
	User string `json:"user"`

	// AuthorizedAt is the ISO 8601 UTC time the authorization was
	// signed.
	AuthorizedAt time.Time `json:"authorized_at"`

	// Scope is the disclosure scope: one of "brief_only",
	// "enclosure_only", or "brief_and_enclosure". A reporting
	// server MUST only disclose content covered by the scope.
	Scope string `json:"scope"`

	// Signature is the user's signature over the canonical form
	// of this authorization with signature.value elided.
	Signature keys.PublicationSignature `json:"signature"`
}

// DisclosureScope values per REPUTATION.md §3.5.
const (
	DisclosureScopeBriefOnly         = "brief_only"
	DisclosureScopeEnclosureOnly     = "enclosure_only"
	DisclosureScopeBriefAndEnclosure = "brief_and_enclosure"
)

// AllowsBrief reports whether this authorization permits disclosing
// decrypted brief content.
func (a *DisclosureAuthorization) AllowsBrief() bool {
	if a == nil {
		return false
	}
	return a.Scope == DisclosureScopeBriefOnly || a.Scope == DisclosureScopeBriefAndEnclosure
}

// AllowsEnclosure reports whether this authorization permits
// disclosing decrypted enclosure content.
func (a *DisclosureAuthorization) AllowsEnclosure() bool {
	if a == nil {
		return false
	}
	return a.Scope == DisclosureScopeEnclosureOnly || a.Scope == DisclosureScopeBriefAndEnclosure
}
