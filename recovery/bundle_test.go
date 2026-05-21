package recovery_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/recovery"
)

// recommendedKDF returns a KDF block satisfying the §2.5 RECOMMENDED
// defaults. Tests that need to round-trip through Argon2id pay the
// real cost so the parameter validation path is also exercised end
// to end; if this becomes prohibitive we can drop to MIN values, but
// today it stays under a second per call on a modern laptop.
func recommendedKDF(t *testing.T) recovery.BundleKDF {
	t.Helper()
	salt := make([]byte, recovery.MinKDFSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("salt: %v", err)
	}
	return recovery.BundleKDF{
		Algorithm:   recovery.KDFAlgorithmArgon2id,
		Salt:        base64.StdEncoding.EncodeToString(salt),
		MemoryKB:    recovery.MinKDFMemoryKB,
		Iterations:  recovery.MinKDFIterations,
		Parallelism: recovery.MinKDFParallelism,
	}
}

// TestNormalizeRecoverySecretPassphrase confirms the passphrase
// normalization rules per RECOVERY.md §3.2: NFKC, surrounding
// whitespace trimmed.
func TestNormalizeRecoverySecretPassphrase(t *testing.T) {
	// "ﬃ" (U+FB03) is the NFKC decomposition target "ffi" - three
	// bytes of input produce three bytes of output, but the bytes
	// themselves change.
	got, err := recovery.NormalizeRecoverySecret(recovery.SecretFormPassphrase, "  long-enough-pass-ﬃ  ")
	if err != nil {
		t.Fatalf("NormalizeRecoverySecret: %v", err)
	}
	if string(got) != "long-enough-pass-ffi" {
		t.Errorf("normalized = %q, want %q", got, "long-enough-pass-ffi")
	}
}

// TestNormalizeRecoverySecretPassphraseTooShort confirms the §3.1
// MinPassphraseBytes hard floor.
func TestNormalizeRecoverySecretPassphraseTooShort(t *testing.T) {
	if _, err := recovery.NormalizeRecoverySecret(recovery.SecretFormPassphrase, "shortie"); err == nil {
		t.Error("NormalizeRecoverySecret accepted sub-minimum passphrase")
	}
}

// TestNormalizeRecoverySecretRecoveryCode confirms the BIP-39 input
// path: words split on whitespace, joined with single ASCII space,
// lowercased.
func TestNormalizeRecoverySecretRecoveryCode(t *testing.T) {
	in := "  Abandon  ABILITY\tAble\nAbout About Above "
	got, err := recovery.NormalizeRecoverySecret(recovery.SecretFormRecoveryCode, in)
	if err != nil {
		t.Fatalf("NormalizeRecoverySecret: %v", err)
	}
	want := "abandon ability able about about above"
	if string(got) != want {
		t.Errorf("normalized = %q, want %q", got, want)
	}
}

// TestNormalizeRecoverySecretEmptyRecoveryCode confirms an
// all-whitespace recovery code is rejected.
func TestNormalizeRecoverySecretEmptyRecoveryCode(t *testing.T) {
	if _, err := recovery.NormalizeRecoverySecret(recovery.SecretFormRecoveryCode, "   \t\n  "); err == nil {
		t.Error("NormalizeRecoverySecret accepted empty recovery code")
	}
}

// TestNormalizeRecoverySecretUnknownForm confirms an unknown form
// is rejected rather than silently passed through.
func TestNormalizeRecoverySecretUnknownForm(t *testing.T) {
	if _, err := recovery.NormalizeRecoverySecret(recovery.SecretForm("emoji"), "anything"); err == nil {
		t.Error("NormalizeRecoverySecret accepted unknown form")
	}
}

// TestDeriveBundleKeyDeterministic confirms identical inputs produce
// identical 32-byte outputs.
func TestDeriveBundleKeyDeterministic(t *testing.T) {
	kdf := recommendedKDF(t)
	secret := []byte("long-enough-passphrase-abc")
	k1, err := recovery.DeriveBundleKey(secret, kdf)
	if err != nil {
		t.Fatalf("DeriveBundleKey #1: %v", err)
	}
	k2, err := recovery.DeriveBundleKey(secret, kdf)
	if err != nil {
		t.Fatalf("DeriveBundleKey #2: %v", err)
	}
	if len(k1) != 32 {
		t.Errorf("bundle key length %d, want 32", len(k1))
	}
	if string(k1) != string(k2) {
		t.Error("DeriveBundleKey not deterministic for identical inputs")
	}
}

// TestDeriveBundleKeyDifferentSalts confirms a salt change yields a
// different key (Argon2id is salt-sensitive by construction; this
// guards against a wiring bug that drops the salt).
func TestDeriveBundleKeyDifferentSalts(t *testing.T) {
	kdf1 := recommendedKDF(t)
	kdf2 := recommendedKDF(t)
	if kdf1.Salt == kdf2.Salt {
		t.Skip("rand.Read collision; rerun")
	}
	secret := []byte("long-enough-passphrase-abc")
	k1, err := recovery.DeriveBundleKey(secret, kdf1)
	if err != nil {
		t.Fatalf("DeriveBundleKey #1: %v", err)
	}
	k2, err := recovery.DeriveBundleKey(secret, kdf2)
	if err != nil {
		t.Fatalf("DeriveBundleKey #2: %v", err)
	}
	if string(k1) == string(k2) {
		t.Error("DeriveBundleKey produced identical keys for different salts")
	}
}

// TestBundleKDFValidateRejectsSubMinimum walks each parameter floor
// and confirms BundleKDF.Validate flags it.
func TestBundleKDFValidateRejectsSubMinimum(t *testing.T) {
	good := recommendedKDF(t)
	cases := []struct {
		name  string
		mut   func(k *recovery.BundleKDF)
	}{
		{"wrong algorithm", func(k *recovery.BundleKDF) { k.Algorithm = "scrypt" }},
		{"empty salt", func(k *recovery.BundleKDF) { k.Salt = "" }},
		{"short salt", func(k *recovery.BundleKDF) {
			k.Salt = base64.StdEncoding.EncodeToString([]byte("too-short"))
		}},
		{"low memory", func(k *recovery.BundleKDF) { k.MemoryKB = recovery.MinKDFMemoryKB - 1 }},
		{"low iterations", func(k *recovery.BundleKDF) { k.Iterations = recovery.MinKDFIterations - 1 }},
		{"low parallelism", func(k *recovery.BundleKDF) { k.Parallelism = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := good
			tc.mut(&k)
			if err := k.Validate(); err == nil {
				t.Error("BundleKDF.Validate accepted a non-conforming KDF")
			}
		})
	}
}

// TestEncryptDecryptBundlePayload exercises the AEAD round-trip.
func TestEncryptDecryptBundlePayload(t *testing.T) {
	bundleKey := make([]byte, 32)
	if _, err := rand.Read(bundleKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}

	payload := recovery.BundlePayload{
		IdentityKey: recovery.IdentityKey{
			Algorithm:  "ed25519",
			PublicKey:  base64.StdEncoding.EncodeToString([]byte("pub-key-bytes")),
			PrivateKey: base64.StdEncoding.EncodeToString([]byte("priv-key-bytes")),
			Created:    time.Now().UTC(),
		},
		EncryptionKeys: []recovery.EncryptionKey{
			{
				Algorithm:  "x25519",
				KeyID:      "ek-1",
				PublicKey:  base64.StdEncoding.EncodeToString([]byte("ek-pub")),
				PrivateKey: base64.StdEncoding.EncodeToString([]byte("ek-priv")),
				Created:    time.Now().UTC(),
			},
		},
	}

	ct, err := recovery.EncryptBundlePayload(bundleKey, nonce, payload)
	if err != nil {
		t.Fatalf("EncryptBundlePayload: %v", err)
	}
	got, err := recovery.DecryptBundlePayload(bundleKey, nonce, ct)
	if err != nil {
		t.Fatalf("DecryptBundlePayload: %v", err)
	}
	if got.IdentityKey.PublicKey != payload.IdentityKey.PublicKey {
		t.Errorf("identity_key.public_key round-trip mismatch")
	}
	if len(got.EncryptionKeys) != 1 || got.EncryptionKeys[0].KeyID != "ek-1" {
		t.Errorf("encryption_keys round-trip mismatch: %+v", got.EncryptionKeys)
	}

	// Tamper one ciphertext byte -> AEAD failure.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0x01
	if _, err := recovery.DecryptBundlePayload(bundleKey, nonce, tampered); err == nil {
		t.Error("DecryptBundlePayload accepted tampered ciphertext")
	}

	// Wrong key -> AEAD failure.
	otherKey := make([]byte, 32)
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := recovery.DecryptBundlePayload(otherKey, nonce, ct); err == nil {
		t.Error("DecryptBundlePayload accepted wrong key")
	}
}

// TestEncryptBundlePayloadRejectsBadNonce confirms a non-24-byte
// nonce is refused - this is the AEAD's invariant, but the helper
// returns the more-actionable error first.
func TestEncryptBundlePayloadRejectsBadNonce(t *testing.T) {
	bundleKey := make([]byte, 32)
	if _, err := rand.Read(bundleKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := recovery.EncryptBundlePayload(bundleKey, make([]byte, 12), recovery.BundlePayload{}); err == nil {
		t.Error("EncryptBundlePayload accepted 12-byte nonce")
	}
}

// TestDeriveRecoverySignKeyDeterministic confirms the HKDF-Expand
// path produces a stable Ed25519 key for a given K_bundle.
func TestDeriveRecoverySignKeyDeterministic(t *testing.T) {
	bundleKey := make([]byte, 32)
	if _, err := rand.Read(bundleKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	priv1, pub1, err := recovery.DeriveRecoverySignKey(bundleKey)
	if err != nil {
		t.Fatalf("DeriveRecoverySignKey #1: %v", err)
	}
	priv2, pub2, err := recovery.DeriveRecoverySignKey(bundleKey)
	if err != nil {
		t.Fatalf("DeriveRecoverySignKey #2: %v", err)
	}
	if string(priv1) != string(priv2) {
		t.Error("DeriveRecoverySignKey not deterministic on private key")
	}
	if string(pub1) != string(pub2) {
		t.Error("DeriveRecoverySignKey not deterministic on public key")
	}
}

// makeBundle builds a syntactically valid BackupBundle around a
// pre-encoded payload ciphertext for sign/verify tests.
func makeBundle(t *testing.T, ciphertext []byte, nonce []byte, recoveryVerifyPK string) *recovery.BackupBundle {
	t.Helper()
	return &recovery.BackupBundle{
		UserID:           "alice@example.com",
		BundleID:         "01J0BUNDLE0000000000000001",
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
		KDF:              recommendedKDF(t),
		PayloadAlgorithm: recovery.BundlePayloadAEAD,
		PayloadNonce:     base64.StdEncoding.EncodeToString(nonce),
		EncryptedPayload: base64.StdEncoding.EncodeToString(ciphertext),
		RecoveryVerifyPK: recovery.RecoveryVerifyPK{
			Algorithm: "ed25519",
			PublicKey: recoveryVerifyPK,
		},
	}
}

// TestSignVerifyBundleRoundTrip exercises the §2.4 outer-signature
// happy path.
func TestSignVerifyBundleRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	idPub, idPriv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	idFP := base64.StdEncoding.EncodeToString(idPub)[:16]

	b := makeBundle(t,
		[]byte("dummy-ciphertext-for-signature-test"),
		make([]byte, chacha20poly1305.NonceSizeX),
		base64.StdEncoding.EncodeToString([]byte("recovery-verify-pk")),
	)
	if err := recovery.SignBundle(signer, idPriv, idFP, b); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	if b.Signature.Value == "" {
		t.Fatal("SignBundle did not populate signature.value")
	}
	if err := recovery.VerifyBundle(signer, idPub, b); err != nil {
		t.Errorf("VerifyBundle: %v", err)
	}
}

// TestVerifyBundleRejectsTamper confirms a mutation to a covered
// field invalidates the signature.
func TestVerifyBundleRejectsTamper(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	idPub, idPriv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	idFP := base64.StdEncoding.EncodeToString(idPub)[:16]

	b := makeBundle(t,
		[]byte("dummy"),
		make([]byte, chacha20poly1305.NonceSizeX),
		base64.StdEncoding.EncodeToString([]byte("rvpk")),
	)
	if err := recovery.SignBundle(signer, idPriv, idFP, b); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	b.UserID = "mallory@attacker.example"
	if err := recovery.VerifyBundle(signer, idPub, b); err == nil {
		t.Error("VerifyBundle accepted tampered user_id")
	}
}

// TestBackupBundleValidateMissingFields walks each required field
// and confirms BackupBundle.Validate flags its absence.
func TestBackupBundleValidateMissingFields(t *testing.T) {
	good := func() *recovery.BackupBundle {
		return makeBundle(t,
			[]byte("dummy"),
			make([]byte, chacha20poly1305.NonceSizeX),
			base64.StdEncoding.EncodeToString([]byte("rvpk")),
		)
	}
	cases := []struct {
		name string
		mut  func(b *recovery.BackupBundle)
	}{
		{"missing user_id", func(b *recovery.BackupBundle) { b.UserID = "" }},
		{"missing bundle_id", func(b *recovery.BackupBundle) { b.BundleID = "" }},
		{"missing created_at", func(b *recovery.BackupBundle) { b.CreatedAt = time.Time{} }},
		{"missing payload_nonce", func(b *recovery.BackupBundle) { b.PayloadNonce = "" }},
		{"missing encrypted_payload", func(b *recovery.BackupBundle) { b.EncryptedPayload = "" }},
		{"wrong payload_algorithm", func(b *recovery.BackupBundle) { b.PayloadAlgorithm = "aes-gcm" }},
		{"missing recovery_verify_pk.public_key", func(b *recovery.BackupBundle) {
			b.RecoveryVerifyPK.PublicKey = ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := good()
			b.Type = recovery.BundleType
			tc.mut(b)
			if err := b.Validate(); err == nil {
				t.Error("BackupBundle.Validate accepted invalid bundle")
			}
		})
	}
}

// TestBundleEndToEnd drives the full §2 flow: a passphrase derives
// K_bundle and the recovery sign-key, encrypts the payload, signs
// the bundle. The "restore" path independently re-derives K_bundle
// from the same passphrase, decrypts, and verifies. This is the
// scenario any conforming client implements end to end.
func TestBundleEndToEnd(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	idPub, idPriv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	idFP := base64.StdEncoding.EncodeToString(idPub)[:16]

	// --- Backup side ---
	secret, err := recovery.NormalizeRecoverySecret(
		recovery.SecretFormPassphrase, "correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("NormalizeRecoverySecret: %v", err)
	}
	kdf := recommendedKDF(t)
	bundleKey, err := recovery.DeriveBundleKey(secret, kdf)
	if err != nil {
		t.Fatalf("DeriveBundleKey: %v", err)
	}
	_, recoveryVerifyPK, err := recovery.DeriveRecoverySignKey(bundleKey)
	if err != nil {
		t.Fatalf("DeriveRecoverySignKey: %v", err)
	}

	payload := recovery.BundlePayload{
		IdentityKey: recovery.IdentityKey{
			Algorithm:  "ed25519",
			PublicKey:  base64.StdEncoding.EncodeToString(idPub),
			PrivateKey: base64.StdEncoding.EncodeToString(idPriv),
			Created:    time.Now().UTC(),
		},
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ct, err := recovery.EncryptBundlePayload(bundleKey, nonce, payload)
	if err != nil {
		t.Fatalf("EncryptBundlePayload: %v", err)
	}

	b := &recovery.BackupBundle{
		UserID:           "alice@example.com",
		BundleID:         "01J0BUNDLE0000000000000002",
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
		KDF:              kdf,
		PayloadAlgorithm: recovery.BundlePayloadAEAD,
		PayloadNonce:     base64.StdEncoding.EncodeToString(nonce),
		EncryptedPayload: base64.StdEncoding.EncodeToString(ct),
		RecoveryVerifyPK: recovery.RecoveryVerifyPK{
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(recoveryVerifyPK),
		},
	}
	if err := recovery.SignBundle(signer, idPriv, idFP, b); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// --- Restore side ---
	if err := recovery.VerifyBundle(signer, idPub, b); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	restoredSecret, err := recovery.NormalizeRecoverySecret(
		recovery.SecretFormPassphrase, "correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("NormalizeRecoverySecret (restore): %v", err)
	}
	restoredKey, err := recovery.DeriveBundleKey(restoredSecret, b.KDF)
	if err != nil {
		t.Fatalf("DeriveBundleKey (restore): %v", err)
	}
	if string(restoredKey) != string(bundleKey) {
		t.Fatal("restore-side K_bundle differs from backup-side")
	}
	gotNonce, err := base64.StdEncoding.DecodeString(b.PayloadNonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	gotCT, err := base64.StdEncoding.DecodeString(b.EncryptedPayload)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	got, err := recovery.DecryptBundlePayload(restoredKey, gotNonce, gotCT)
	if err != nil {
		t.Fatalf("DecryptBundlePayload (restore): %v", err)
	}
	if got.IdentityKey.PublicKey != payload.IdentityKey.PublicKey {
		t.Error("restored identity_key.public_key mismatch")
	}
	if got.IdentityKey.PrivateKey != payload.IdentityKey.PrivateKey {
		t.Error("restored identity_key.private_key mismatch")
	}

	// Wrong passphrase -> wrong K_bundle -> AEAD open fails.
	wrongSecret, err := recovery.NormalizeRecoverySecret(
		recovery.SecretFormPassphrase, "incorrect horse battery staple",
	)
	if err != nil {
		t.Fatalf("NormalizeRecoverySecret (wrong): %v", err)
	}
	wrongKey, err := recovery.DeriveBundleKey(wrongSecret, b.KDF)
	if err != nil {
		t.Fatalf("DeriveBundleKey (wrong): %v", err)
	}
	if _, err := recovery.DecryptBundlePayload(wrongKey, gotNonce, gotCT); err == nil {
		t.Error("DecryptBundlePayload accepted ciphertext under wrong passphrase")
	}
}

// TestSignBundleRequiresIdentityFingerprint confirms the signing
// path enforces the identity-key fingerprint argument; the bundle's
// signature.key_id is the user's CURRENT identity-key fingerprint
// per §2.4 and consumers index successor records on that value.
func TestSignBundleRequiresIdentityFingerprint(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	b := makeBundle(t,
		[]byte("dummy"),
		make([]byte, chacha20poly1305.NonceSizeX),
		base64.StdEncoding.EncodeToString([]byte("rvpk")),
	)
	if err := recovery.SignBundle(signer, idPriv, "", b); err == nil {
		t.Error("SignBundle accepted empty identity key fingerprint")
	}
	if err := recovery.SignBundle(signer, nil, "fp", b); err == nil {
		t.Error("SignBundle accepted nil identity private key")
	}
}

// TestVerifyBundleRejectsUnsigned confirms a bundle missing its
// signature.value is rejected at the verification gate.
func TestVerifyBundleRejectsUnsigned(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	idPub, _, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	b := makeBundle(t,
		[]byte("dummy"),
		make([]byte, chacha20poly1305.NonceSizeX),
		base64.StdEncoding.EncodeToString([]byte("rvpk")),
	)
	b.Type = recovery.BundleType
	if err := recovery.VerifyBundle(signer, idPub, b); err == nil {
		t.Error("VerifyBundle accepted unsigned bundle")
	}
}
