package keys

import (
	"time"

	semp "semp.dev/semp-go"
)

// RequestType is the wire-level type discriminator for SEMP_KEYS messages
// (CLIENT.md §5.4, KEY.md §4).
const RequestType = "SEMP_KEYS"

// RequestStep is the message-variant discriminator for SEMP_KEYS.
type RequestStep string

// RequestStep values.
const (
	RequestStepRequest  RequestStep = "request"
	RequestStepResponse RequestStep = "response"
)

// Request is the SEMP_KEYS request schema (CLIENT.md §5.4.1). Clients send
// this over their authenticated session to ask the home server for one or
// more recipient users' published keys. The home server fulfills the
// request from its cache or by fetching from the remote domain's
// well-known URI / federation session and returns a Response.
type Request struct {
	Type              string      `json:"type"`
	Step              RequestStep `json:"step"`
	Version           string      `json:"version"`
	ID                string      `json:"id"`
	Timestamp         time.Time   `json:"timestamp"`
	Addresses         []string    `json:"addresses"`
	IncludeDomainKeys bool        `json:"include_domain_keys"`
}

// NewRequest constructs a SEMP_KEYS request with `version` and `timestamp`
// pre-populated and `include_domain_keys` set to the spec default of true.
func NewRequest(id string, addresses []string) *Request {
	return &Request{
		Type:              RequestType,
		Step:              RequestStepRequest,
		Version:           semp.ProtocolVersion,
		ID:                id,
		Timestamp:         time.Now().UTC(),
		Addresses:         addresses,
		IncludeDomainKeys: true,
	}
}

// Response is the SEMP_KEYS response schema (CLIENT.md §5.4.3). The home
// server returns one ResponseResult per requested address; `status`
// indicates whether the lookup succeeded.
type Response struct {
	Type      string           `json:"type"`
	Step      RequestStep      `json:"step"`
	Version   string           `json:"version"`
	ID        string           `json:"id"`
	Timestamp time.Time        `json:"timestamp"`
	Results   []ResponseResult `json:"results"`
}

// NewResponse builds a Response that echoes the request id, with the
// current UTC timestamp.
func NewResponse(requestID string, results []ResponseResult) *Response {
	return &Response{
		Type:      RequestType,
		Step:      RequestStepResponse,
		Version:   semp.ProtocolVersion,
		ID:        requestID,
		Timestamp: time.Now().UTC(),
		Results:   results,
	}
}

// ResponseResult is one entry in Response.Results (CLIENT.md §5.4.5).
// Status values are "found", "not_found", or "error". The ErrorReason
// field is populated for "error" status only.
type ResponseResult struct {
	// Address is the requested user address.
	Address string `json:"address"`

	// Status is the per-address lookup outcome.
	Status ResultStatus `json:"status"`

	// Domain is the recipient's domain (the suffix of Address after
	// the '@'). Always populated.
	Domain string `json:"domain"`

	// DomainKey is the recipient server's domain signing/encryption
	// key record. Present when include_domain_keys was true in the
	// request and Status is StatusFound.
	//
	// Note: the spec treats the domain key as a single record; in
	// practice we need to publish both a signing key (Ed25519) and an
	// encryption key (X25519) per the dual-key model in KEY.md §1.1.
	// The demo binary populates DomainKey with the signing key and
	// adds the encryption key as a separate entry in UserKeys with a
	// synthetic "domain" address; real implementations would extend
	// the key record schema to carry both roles.
	DomainKey *Record `json:"domain_key,omitempty"`

	// DomainEncKey is the recipient server's domain encryption key
	// record. Present when include_domain_keys was true in the
	// request and Status is StatusFound. This is an extension field
	// beyond the literal CLIENT.md §5.4.3 schema; see DomainKey for
	// context.
	DomainEncKey *Record `json:"domain_enc_key,omitempty"`

	// UserKeys is the per-user key set. Typically includes one
	// identity key and one encryption key per user. Always populated
	// when Status is StatusFound (possibly empty if the user has no
	// keys of the requested types).
	UserKeys []*Record `json:"user_keys"`

	// OriginSignature carries the remote domain's signature over the
	// key material as received from the remote well-known URI, per
	// CLIENT.md §5.4.5. The demo home server does not re-sign key
	// material, so this field may be nil for locally-served results.
	OriginSignature *Signature `json:"origin_signature,omitempty"`

	// ErrorReason is a human-readable diagnostic, populated only when
	// Status is StatusError.
	ErrorReason string `json:"error_reason,omitempty"`
}

// ResultStatus is the per-address status in a Response.
type ResultStatus string

// ResultStatus values.
const (
	StatusFound    ResultStatus = "found"
	StatusNotFound ResultStatus = "not_found"
	StatusError    ResultStatus = "error"
)
