package delivery

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/canonical"
)

// SEMP_USER_POLICY message constants per DELIVERY.md §7.1.
const (
	UserPolicyType    = "SEMP_USER_POLICY"
	UserPolicyStep    = "update"
	UserPolicyVersion = "1.0.0"
)

// PolicyOp names the verb of a policy operation per §7.1. The set
// is closed: extensibility comes via new Kind values, not new
// verbs.
type PolicyOp string

// Policy operation verbs.
const (
	PolicyOpAdd    PolicyOp = "add"
	PolicyOpRemove PolicyOp = "remove"
	PolicyOpModify PolicyOp = "modify"
)

// Defined policy rule kinds per §7.3. Operators MAY define
// additional kinds via the §7.2 namespaced-identifier rule; the
// home server rejects unknown kinds with reason_code
// "policy_kind_unsupported" per §7.2.
const (
	PolicyKindBlock           = "semp.dev/block"
	PolicyKindAcceptedSender  = "semp.dev/accepted_sender"
	PolicyKindFirstContact    = "semp.dev/first_contact"
)

// PolicyOperation is one entry inside a UserPolicyMessage's
// operations array per §7.1. EntryID is set on remove and modify
// references; Entry carries the new entry shape on add and modify.
// The field set deliberately allows raw json.RawMessage for Entry
// because the inner shape varies by Kind (block-entry,
// accepted-sender, singleton first-contact).
type PolicyOperation struct {
	Op      PolicyOp        `json:"op"`
	Kind    string          `json:"kind"`
	EntryID string          `json:"entry_id,omitempty"`
	Entry   json.RawMessage `json:"entry,omitempty"`
}

// UserPolicyMessage is a SEMP_USER_POLICY update record per
// DELIVERY.md §7.1. The signature is by the originating device's
// device key, computed over the canonical record bytes with
// signature.value elided, prefixed with SEMP-USER-POLICY:.
type UserPolicyMessage struct {
	Type           string            `json:"type"`
	Step           string            `json:"step"`
	Version        string            `json:"version"`
	UserID         string            `json:"user_id"`
	DeviceID       string            `json:"device_id"`
	PolicyVersion  int64             `json:"policy_version"`
	Timestamp      time.Time         `json:"timestamp"`
	Operations     []PolicyOperation `json:"operations"`
	Signature      ReceiptSignature  `json:"signature"`
}

// canonicalUserPolicyBytes returns the canonical JSON form of m
// with signature.value elided to "".
func canonicalUserPolicyBytes(m *UserPolicyMessage) ([]byte, error) {
	if m == nil {
		return nil, errors.New("delivery: nil user policy message")
	}
	return canonical.MarshalWithElision(m, func(v any) error {
		root, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("delivery: expected top-level object, got %T", v)
		}
		sig, ok := root["signature"].(map[string]any)
		if !ok {
			return errors.New("delivery: user policy missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignUserPolicyMessage populates m.Signature with the originating
// device's signature over the canonical record bytes per §7.1.
func SignUserPolicyMessage(signer crypto.Signer, devicePriv []byte, deviceKeyID string, m *UserPolicyMessage) error {
	if signer == nil {
		return errors.New("delivery: nil signer")
	}
	if m == nil {
		return errors.New("delivery: nil user policy message")
	}
	if len(devicePriv) == 0 {
		return errors.New("delivery: empty device private key")
	}
	if deviceKeyID == "" {
		return errors.New("delivery: empty device key fingerprint")
	}
	if m.Type == "" {
		m.Type = UserPolicyType
	}
	if m.Step == "" {
		m.Step = UserPolicyStep
	}
	if m.Version == "" {
		m.Version = UserPolicyVersion
	}
	if err := m.Validate(); err != nil {
		return err
	}
	m.Signature.Algorithm = ReceiptSignatureAlgorithmEd25519
	m.Signature.KeyID = deviceKeyID
	m.Signature.Value = ""
	canonicalBytes, err := canonicalUserPolicyBytes(m)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxUserPolicy, canonicalBytes)
	sig, err := signer.Sign(devicePriv, prefixed)
	if err != nil {
		return fmt.Errorf("delivery: sign user policy: %w", err)
	}
	m.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyUserPolicyMessage checks m.Signature against devicePub per
// §7.1 / §9.2.
func VerifyUserPolicyMessage(signer crypto.Signer, devicePub []byte, m *UserPolicyMessage) error {
	if signer == nil {
		return errors.New("delivery: nil signer")
	}
	if m == nil {
		return errors.New("delivery: nil user policy message")
	}
	if len(devicePub) == 0 {
		return errors.New("delivery: empty device public key")
	}
	if m.Signature.Value == "" {
		return errors.New("delivery: user policy is unsigned")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature.Value)
	if err != nil {
		return fmt.Errorf("delivery: user policy signature base64: %w", err)
	}
	canonicalBytes, err := canonicalUserPolicyBytes(m)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxUserPolicy, canonicalBytes)
	if err := signer.Verify(devicePub, prefixed, sig); err != nil {
		return fmt.Errorf("delivery: verify user policy: %w", err)
	}
	return nil
}

// Validate reports whether m is structurally well-formed per §7.1
// and the §7.3 op-kind validity rules. Singleton-shaped kinds
// (semp.dev/first_contact) accept only modify; list-shaped kinds
// accept add, remove, and modify with the entry_id rules in §7.3.
func (m *UserPolicyMessage) Validate() error {
	if m == nil {
		return errors.New("delivery: nil user policy message")
	}
	if m.Type != UserPolicyType {
		return fmt.Errorf("delivery: user policy type %q, want %q", m.Type, UserPolicyType)
	}
	if m.Step != UserPolicyStep {
		return fmt.Errorf("delivery: user policy step %q, want %q", m.Step, UserPolicyStep)
	}
	if m.UserID == "" {
		return errors.New("delivery: user policy missing user_id")
	}
	if m.DeviceID == "" {
		return errors.New("delivery: user policy missing device_id")
	}
	if m.PolicyVersion < 1 {
		return fmt.Errorf("delivery: user policy policy_version %d MUST be >= 1", m.PolicyVersion)
	}
	if m.Timestamp.IsZero() {
		return errors.New("delivery: user policy missing timestamp")
	}
	if len(m.Operations) == 0 {
		return errors.New("delivery: user policy operations MUST be non-empty")
	}
	for i, op := range m.Operations {
		if err := op.validate(); err != nil {
			return fmt.Errorf("delivery: user policy operations[%d]: %w", i, err)
		}
	}
	return nil
}

func (op PolicyOperation) validate() error {
	switch op.Op {
	case PolicyOpAdd, PolicyOpRemove, PolicyOpModify:
		// ok
	case "":
		return errors.New("missing op")
	default:
		return fmt.Errorf("op %q is not in the closed set {add, remove, modify}", op.Op)
	}
	if op.Kind == "" {
		return errors.New("missing kind")
	}
	// Singleton kinds accept only modify per §7.3.
	switch op.Kind {
	case PolicyKindFirstContact:
		if op.Op != PolicyOpModify {
			return fmt.Errorf("singleton kind %q accepts only modify, got %s", op.Kind, op.Op)
		}
		if op.EntryID != "" {
			return fmt.Errorf("singleton kind %q MUST NOT carry entry_id", op.Kind)
		}
		if len(op.Entry) == 0 {
			return fmt.Errorf("singleton kind %q modify MUST carry entry", op.Kind)
		}
	}
	// List-shaped kinds: remove/modify reference by entry_id; add
	// supplies a new entry.
	if op.Op == PolicyOpRemove && op.EntryID == "" {
		return errors.New("remove op MUST set entry_id")
	}
	if op.Op == PolicyOpAdd && len(op.Entry) == 0 {
		return errors.New("add op MUST carry entry")
	}
	return nil
}
