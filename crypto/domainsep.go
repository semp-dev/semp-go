package crypto

// Domain separation prefixes for Ed25519 signatures. Each SEMP context
// that signs with any signing key prepends a unique prefix to the
// message before signing. This prevents cross-context signature
// confusion where a signature valid in one context could be
// misinterpreted in another.
//
// The authoritative registry of contexts lives in ENVELOPE.md section
// 4.3. Every signed SEMP record MUST use one of the prefixes below.
// New contexts are added here when the spec introduces them.
const (
	// SigCtxHandshake prefixes handshake message signatures.
	SigCtxHandshake = "SEMP-HANDSHAKE:"

	// SigCtxEnvelope prefixes envelope seal signatures.
	SigCtxEnvelope = "SEMP-ENVELOPE:"

	// SigCtxKeys prefixes key response signatures.
	SigCtxKeys = "SEMP-KEYS:"

	// SigCtxKeySelfSig prefixes a user's self-signature over their own
	// encryption key record (KEY.md section 5.2).
	SigCtxKeySelfSig = "SEMP-KEY-SELF-SIG:"

	// SigCtxDiscovery prefixes discovery response signatures.
	SigCtxDiscovery = "SEMP-DISCOVERY:"

	// SigCtxIdentity prefixes identity proof signatures in the handshake.
	SigCtxIdentity = "SEMP-IDENTITY:"

	// SigCtxRevocation prefixes key revocation signatures (KEY.md
	// section 8.1).
	SigCtxRevocation = "SEMP-REVOCATION:"

	// SigCtxDeliveryReceipt prefixes signed delivery receipts
	// (DELIVERY.md section 1.1.1).
	SigCtxDeliveryReceipt = "SEMP-DELIVERY-RECEIPT:"

	// SigCtxRecoveryBundle prefixes the outer signature on a backup
	// bundle for account recovery (RECOVERY.md section 2.4).
	SigCtxRecoveryBundle = "SEMP-RECOVERY-BUNDLE:"

	// SigCtxRecoveryManifest prefixes the Shamir recovery-set manifest
	// signature produced by the user's identity key (RECOVERY.md
	// section 5.2).
	SigCtxRecoveryManifest = "SEMP-RECOVERY-MANIFEST:"

	// SigCtxRecoveryShare prefixes the per-device signature on a Shamir
	// share record (RECOVERY.md section 5.3).
	SigCtxRecoveryShare = "SEMP-RECOVERY-SHARE:"

	// SigCtxSuccessorRecord prefixes all three signatures on a
	// successor record (RECOVERY.md section 7.3). The three signatures
	// share the prefix and are differentiated by the signing key.
	SigCtxSuccessorRecord = "SEMP-SUCCESSOR-RECORD:"

	// SigCtxMigrationRecord prefixes all four signatures on a migration
	// record (MIGRATION.md section 3.3). The four signatures share the
	// prefix and are differentiated by the signing key and by the set
	// of prior signatures embedded in the canonical bytes.
	SigCtxMigrationRecord = "SEMP-MIGRATION-RECORD:"

	// SigCtxDeviceRegister prefixes the outer identity-key signature on
	// a SEMP_DEVICE registration record (KEY.md section 10.1).
	SigCtxDeviceRegister = "SEMP-DEVICE-REGISTER:"

	// SigCtxDeviceAuthorize prefixes the authorizing device-key
	// signature inside a SEMP_DEVICE registration record (KEY.md
	// section 10.2.2).
	SigCtxDeviceAuthorize = "SEMP-DEVICE-AUTHORIZE:"

	// SigCtxDeviceRevocation prefixes the identity-key signature on a
	// SEMP_DEVICE_REVOCATION record (KEY.md section 10.5).
	SigCtxDeviceRevocation = "SEMP-DEVICE-REVOCATION:"

	// SigCtxDeviceDirectory prefixes the identity-key signature on a
	// SEMP_DEVICE_DIRECTORY record (KEY.md section 10.6).
	SigCtxDeviceDirectory = "SEMP-DEVICE-DIRECTORY:"
)

// PrefixedMessage prepends a domain-separation context prefix to a message.
func PrefixedMessage(prefix string, message []byte) []byte {
	out := make([]byte, len(prefix)+len(message))
	copy(out, prefix)
	copy(out[len(prefix):], message)
	return out
}
