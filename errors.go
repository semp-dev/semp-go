package semp

import (
	"errors"
	"fmt"
)

// Error is the structured error type returned by every SEMP operation that
// can fail with a machine-readable reason. Callers branch on Code via
// errors.As; the human-readable Message is for diagnostics and user display
// and MUST NOT be parsed programmatically (ERRORS.md §14.1).
//
// Wrapped, when non-nil, holds the underlying cause (a transport failure,
// crypto error, JSON parse error, etc.) and is exposed via Unwrap so that
// errors.Is and errors.As traverse the chain in the usual way.
type Error struct {
	// Code is the SEMP reason code that classifies this failure.
	Code ReasonCode

	// Message is a human-readable description suitable for logs and UIs.
	// It is operator-facing only; do not parse it.
	Message string

	// Wrapped is the underlying cause, if any.
	Wrapped error
}

// Errorf constructs a new Error with a formatted message and no wrapped
// cause.
func Errorf(code ReasonCode, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WrapErr constructs a new Error wrapping cause with the given code.
func WrapErr(code ReasonCode, cause error, format string, args ...any) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Wrapped: cause,
	}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Wrapped != nil {
		return fmt.Sprintf("semp: %s: %s: %v", e.Code, e.Message, e.Wrapped)
	}
	return fmt.Sprintf("semp: %s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped cause for errors.Is / errors.As traversal.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Wrapped
}

// Is reports whether target is a *semp.Error with the same Code. This makes
// `errors.Is(err, &semp.Error{Code: semp.ReasonBlocked})` work for callers
// that want a quick code-only comparison.
func (e *Error) Is(target error) bool {
	if e == nil {
		return target == nil
	}
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return t.Code == e.Code
}

// Recoverable reports whether the error's reason code is recoverable
// per the table in ERRORS.md.
func (e *Error) Recoverable() bool {
	if e == nil {
		return false
	}
	return e.Code.Recoverable()
}

// CodeOf returns the ReasonCode of err if err is a *semp.Error, or the empty
// string otherwise. It is the convenient extraction helper for callers that
// only care about the code.
func CodeOf(err error) ReasonCode {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
