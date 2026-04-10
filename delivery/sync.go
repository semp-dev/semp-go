package delivery

import (
	"time"

	"github.com/semp-dev/semp-go/keys"
)

// SyncMessageType is the wire-level type discriminator for block list sync
// messages (DELIVERY.md §6.1).
const SyncMessageType = "SEMP_BLOCK"

// SyncStep is the only defined step.
const SyncStep = "update"

// SyncOp identifies the kind of sync operation.
type SyncOp string

// Defined sync operations.
const (
	OpAdd    SyncOp = "add"
	OpRemove SyncOp = "remove"
	OpModify SyncOp = "modify"
)

// SyncOperation is one entry in a SyncMessage's operations array.
type SyncOperation struct {
	Op      SyncOp      `json:"op"`
	EntryID string      `json:"entry_id,omitempty"` // for remove and modify
	Entry   *BlockEntry `json:"entry,omitempty"`    // for add and modify
}

// SyncMessage is the SEMP_BLOCK sync message used to propagate block list
// changes from a client to its home server and onward to the user's other
// devices (DELIVERY.md §6.1).
//
// The message MUST be signed by the originating device's key. The home
// server MUST verify the signature before storing or propagating
// (DELIVERY.md §6.2, §8.2).
type SyncMessage struct {
	Type        string                    `json:"type"`
	Step        string                    `json:"step"`
	Version     string                    `json:"version"`
	UserID      string                    `json:"user_id"`
	DeviceID    string                    `json:"device_id"`
	ListVersion uint64                    `json:"list_version"`
	Timestamp   time.Time                 `json:"timestamp"`
	Operations  []SyncOperation           `json:"operations"`
	Signature   keys.PublicationSignature `json:"signature"`
}

// Verify checks the signature on a SyncMessage. Returns nil if the signature
// is valid against the originating device's key.
//
// TODO(DELIVERY.md §6.2): implement using crypto.Signer.
func (m *SyncMessage) Verify(deviceKey []byte) error {
	_, _ = m, deviceKey
	return nil
}
