package extensions

// DefinitionPathPrefix is the canonical URL path prefix at which an
// extension's definition document is published per EXTENSIONS.md
// §3.5 and RFC 8615. The full URL is
// "https://<host>" + DefinitionPathPrefix + "<name>.json" where
// <host>/<name> together form the extension identifier (such as
// "semp.dev/foo" or "vendor.example.com/feature1").
const DefinitionPathPrefix = "/.well-known/semp-extensions/"

// DefinitionURL returns the canonical definition-document URL for
// an extension identifier of the form "<host>/<name>" per
// EXTENSIONS.md §6. Implementations consulting an extension
// definition MUST request this canonical form; servers MUST NOT
// publish definition documents only at a legacy path.
//
// Returns the empty string if id does not contain a "/" separator.
func DefinitionURL(id string) string {
	for i := 0; i < len(id); i++ {
		if id[i] == '/' && i > 0 && i < len(id)-1 {
			host := id[:i]
			name := id[i+1:]
			return "https://" + host + DefinitionPathPrefix + name + ".json"
		}
	}
	return ""
}

// ValidationFailureCode is the informational diagnostic carried by
// a single entry in an extension_unsupported rejection's `errors`
// array per EXTENSIONS.md §3.9.3. The value identifies which
// runtime validation rule failed; the same reason_code
// (`extension_unsupported`) is reused for every rule.
type ValidationFailureCode string

// Defined ValidationFailureCode values per EXTENSIONS.md §3.9.3.
const (
	// ValidationDefinitionUnfetchable: the extension's definition
	// document could not be fetched (network failure, 404, etc.).
	ValidationDefinitionUnfetchable ValidationFailureCode = "definition_unfetchable"

	// ValidationDefinitionSignatureInvalid: signature on the
	// definition document does not verify under the issuing key.
	ValidationDefinitionSignatureInvalid ValidationFailureCode = "definition_signature_invalid"

	// ValidationDataSchemaMismatch: the entry's `data` field does
	// not conform to the definition's `data_schema`.
	ValidationDataSchemaMismatch ValidationFailureCode = "data_schema_mismatch"

	// ValidationPlacementViolation: the entry appeared in a layer
	// not listed in the definition's `placement.allowed_layers`.
	ValidationPlacementViolation ValidationFailureCode = "placement_violation"

	// ValidationAuthorityViolation: the producing party (inferred
	// from envelope context) is not listed in the definition's
	// `authority.produced_by`.
	ValidationAuthorityViolation ValidationFailureCode = "authority_violation"

	// ValidationDependencyUnsatisfied: a required dependency is not
	// present in the envelope or advertised in capability
	// negotiation.
	ValidationDependencyUnsatisfied ValidationFailureCode = "dependency_unsatisfied"

	// ValidationConflictPresent: a declared conflict is present in
	// the envelope alongside this entry.
	ValidationConflictPresent ValidationFailureCode = "conflict_present"
)

// ValidationFailureItem is one entry in the §3.9.3 `errors` array.
// Each entry pairs the failing extension identifier with a
// diagnostic.
type ValidationFailureItem struct {
	Extension         string                `json:"extension"`
	ValidationFailure ValidationFailureCode `json:"validation_failure"`
}

// ValidationFailureRejection is the §3.9.3 envelope-rejection wire
// shape carrying one or more validation failures. The
// reason_code is always `extension_unsupported`; the per-rule
// diagnostic lives in each errors[i].validation_failure entry so
// a single rejection can report multiple failures from the same
// envelope.
type ValidationFailureRejection struct {
	Type       string                  `json:"type"`
	Step       string                  `json:"step"`
	Version    string                  `json:"version"`
	ReasonCode string                  `json:"reason_code"`
	Reason     string                  `json:"reason"`
	Errors     []ValidationFailureItem `json:"errors"`
}

// NewValidationFailureRejection wraps items in the standard §3.9.3
// rejection shape. Reason defaults to "Extension validation
// failed" when empty.
func NewValidationFailureRejection(items []ValidationFailureItem, reason string) ValidationFailureRejection {
	if reason == "" {
		reason = "Extension validation failed"
	}
	return ValidationFailureRejection{
		Type:       "SEMP_ENVELOPE",
		Step:       "rejected",
		Version:    "1.0.0",
		ReasonCode: "extension_unsupported",
		Reason:     reason,
		Errors:     items,
	}
}
