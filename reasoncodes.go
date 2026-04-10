package semp

// ReasonCode is a machine-readable rejection reason returned by handshake,
// envelope, rekey, and submission operations. Reason codes are lowercase
// snake_case strings; matching is case-sensitive per ERRORS.md §14.3.
//
// Reason codes appear in the `reason_code` field of every structured
// rejection in the protocol. Their authoritative semantics live in the
// originating spec; this file mirrors the registry in ERRORS.md.
type ReasonCode string

// Handshake reason codes (HANDSHAKE.md §4.1, ERRORS.md §2).
const (
	ReasonBlocked          ReasonCode = "blocked"
	ReasonAuthFailed       ReasonCode = "auth_failed"
	ReasonPolicyViolation  ReasonCode = "policy_violation"
	ReasonHandshakeExpired ReasonCode = "handshake_expired"
	ReasonHandshakeInvalid ReasonCode = "handshake_invalid"
	ReasonNoSession        ReasonCode = "no_session"
	ReasonRateLimited      ReasonCode = "rate_limited"
	ReasonPoWRequired      ReasonCode = "pow_required"
	ReasonPoWFailed        ReasonCode = "pow_failed"
	ReasonServerAtCapacity ReasonCode = "server_at_capacity"
)

// Envelope reason codes (ENVELOPE.md §9.3, ERRORS.md §3). Several handshake
// codes also appear at the envelope layer with the same meaning; only the
// envelope-specific additions are declared here.
const (
	ReasonSealInvalid           ReasonCode = "seal_invalid"
	ReasonSessionMACInvalid     ReasonCode = "session_mac_invalid"
	ReasonEnvelopeExpired       ReasonCode = "envelope_expired"
	ReasonExtensionUnsupported  ReasonCode = "extension_unsupported"
	ReasonExtensionSizeExceeded ReasonCode = "extension_size_exceeded"
	ReasonScopeExceeded         ReasonCode = "scope_exceeded"
)

// Rekey reason codes (SESSION.md §3.2, ERRORS.md §4).
const (
	ReasonSessionExpired   ReasonCode = "session_expired"
	ReasonRekeyUnsupported ReasonCode = "rekey_unsupported"
)

// Recoverable reports whether automated retry is appropriate for this reason
// code without user intervention. The mapping is taken directly from the
// recoverability columns in ERRORS.md §2 through §4.
//
// A non-recoverable code means the sender server MUST NOT retry automatically
// and SHOULD surface the failure to the originating user.
func (c ReasonCode) Recoverable() bool {
	switch c {
	case ReasonHandshakeExpired,
		ReasonHandshakeInvalid,
		ReasonNoSession,
		ReasonRateLimited,
		ReasonPoWRequired,
		ReasonPoWFailed,
		ReasonServerAtCapacity:
		return true
	default:
		// Includes ReasonSessionExpired and ReasonRekeyUnsupported, which
		// require a fresh handshake rather than an automated retry on the
		// rekey path.
		return false
	}
}

// String satisfies fmt.Stringer.
func (c ReasonCode) String() string { return string(c) }

// Acknowledgment is a protocol-level delivery outcome returned by a recipient
// server to a sending server. Exactly one of these three values is produced
// by every delivery attempt.
//
// Reference: DELIVERY.md §1, ERRORS.md §10.
type Acknowledgment string

// Acknowledgment outcomes.
const (
	// AckDelivered means the recipient server accepted the envelope and will
	// deliver it to the recipient client. Returning this for an envelope the
	// server does not intend to deliver is prohibited (DELIVERY.md §1.1).
	AckDelivered Acknowledgment = "delivered"

	// AckRejected means the recipient server explicitly refused the envelope
	// with a reason code. This is the RECOMMENDED default for any envelope
	// the server will not deliver (DELIVERY.md §1.2).
	AckRejected Acknowledgment = "rejected"

	// AckSilent means the recipient server did not respond within the
	// sender's timeout window. Permitted for deliberate privacy or
	// anti-harassment policy only (DELIVERY.md §1.3).
	AckSilent Acknowledgment = "silent"
)

// String satisfies fmt.Stringer.
func (a Acknowledgment) String() string { return string(a) }

// SubmissionStatus is a per-recipient delivery outcome returned by a home
// server to a client in a SEMP_SUBMISSION response.
//
// Reference: CLIENT.md §6.3, ERRORS.md §5.
type SubmissionStatus string

// SubmissionStatus values.
const (
	StatusDelivered         SubmissionStatus = "delivered"
	StatusRejected          SubmissionStatus = "rejected"
	StatusSilent            SubmissionStatus = "silent"
	StatusLegacyRequired    SubmissionStatus = "legacy_required"
	StatusRecipientNotFound SubmissionStatus = "recipient_not_found"
	StatusQueued            SubmissionStatus = "queued"
)

// Terminal reports whether this submission status is the final outcome.
// Only StatusQueued is non-terminal: the server MUST follow up with a
// delivery event when a queued envelope resolves.
func (s SubmissionStatus) Terminal() bool {
	return s != StatusQueued
}

// String satisfies fmt.Stringer.
func (s SubmissionStatus) String() string { return string(s) }

// DiscoveryStatus is a per-address discovery outcome returned in a
// SEMP_DISCOVERY response result object.
//
// Reference: DISCOVERY.md §4.6, ERRORS.md §6.
type DiscoveryStatus string

// DiscoveryStatus values.
const (
	DiscoverySEMP     DiscoveryStatus = "semp"
	DiscoveryLegacy   DiscoveryStatus = "legacy"
	DiscoveryNotFound DiscoveryStatus = "not_found"
)

// String satisfies fmt.Stringer.
func (s DiscoveryStatus) String() string { return string(s) }

// ToSubmissionStatus maps a discovery outcome to the submission status that
// the home server returns to the client per DISCOVERY.md §7.1: semp →
// proceed, legacy → legacy_required, not_found → recipient_not_found.
func (s DiscoveryStatus) ToSubmissionStatus() SubmissionStatus {
	switch s {
	case DiscoverySEMP:
		return StatusDelivered
	case DiscoveryLegacy:
		return StatusLegacyRequired
	case DiscoveryNotFound:
		return StatusRecipientNotFound
	default:
		return StatusRejected
	}
}

// KeyRequestStatus is a per-address result status returned by a home server
// in a SEMP_KEYS response to a client.
//
// Reference: CLIENT.md §5.4.5, ERRORS.md §7.
type KeyRequestStatus string

// KeyRequestStatus values.
const (
	KeysFound    KeyRequestStatus = "found"
	KeysNotFound KeyRequestStatus = "not_found"
	KeysError    KeyRequestStatus = "error"
)

// String satisfies fmt.Stringer.
func (s KeyRequestStatus) String() string { return string(s) }
