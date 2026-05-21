package delivery

// Device-sync extension marker per draft-gokce-semp-client §5.6.
// Every sync envelope MUST carry the marker in `brief.extensions`
// with `required: true`. The marker's `data` object carries a
// single `kind` field that names the sync category; each sync
// kind declares the `kind` value it produces.
//
// The marker lives in the brief so the home server can apply
// correct policy without decrypting the enclosure. Clients
// receiving an envelope with this marker MUST NOT surface the
// envelope as ordinary correspondence in any mailbox view.
const (
	// DeviceSyncExtensionID is the namespaced identifier of the
	// device-sync marker extension.
	DeviceSyncExtensionID = "semp.dev/device-sync"
)

// DeviceSyncMarkerData is the content of the device-sync
// extension's `data` field per §5.6.
type DeviceSyncMarkerData struct {
	// Kind identifies the sync category. Each sync extension
	// declares the Kind value it produces.
	Kind string `json:"kind"`
}
