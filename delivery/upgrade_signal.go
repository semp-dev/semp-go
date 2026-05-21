package delivery

// SEMP upgrade-signaling SMTP headers per
// draft-gokce-semp-client §5.7. A SEMP-capable client SHOULD
// include these on every outbound SMTP message so a receiving
// SEMP-capable client can offer a thread upgrade without an
// additional DNS lookup. A recipient client that acts on the
// signal MUST verify the advertised identity by completing SEMP
// discovery against UpgradeHeaderDomain and fetching the
// identity key from that domain before treating the upgrade as
// trusted.
//
// The signal is unauthenticated at the SMTP layer; treat the
// headers as a hint only.
const (
	// UpgradeHeaderCapability is the boolean-style header name set
	// to UpgradeCapabilityPresent ("1") whenever the sender's
	// client can receive via SEMP at a published SEMP address.
	UpgradeHeaderCapability = "SEMP-Capability"

	// UpgradeHeaderIdentity carries the fingerprint of the sender's
	// current SEMP identity public key in "<algorithm>:<hex>" form
	// (for example "ed25519:abc123...").
	UpgradeHeaderIdentity = "SEMP-Identity"

	// UpgradeHeaderDomain names the sender's SEMP domain (the
	// domain part of the sender's SEMP address). MAY differ from
	// the domain of the SMTP From header.
	UpgradeHeaderDomain = "SEMP-Domain"

	// UpgradeHeaderAddress carries the full SEMP address of the
	// sender so the recipient does not have to infer it from the
	// From local-part when the SMTP and SEMP local-parts differ.
	UpgradeHeaderAddress = "SEMP-Address"

	// UpgradeCapabilityPresent is the value the sender writes into
	// the SEMP-Capability header. Single fixed value; future
	// versions of the spec may extend the vocabulary.
	UpgradeCapabilityPresent = "1"
)
