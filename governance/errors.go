package governance

import (
	"errors"
	"fmt"
)

// ParseError indicates that an adapter could not construct a valid
// GovernanceRequest from its transport-specific input. The pipeline was
// never invoked. Callers should treat ParseError as deny-equivalent:
// no audit event is emitted by the governance pipeline for these
// failures, and the underlying tool call must not proceed.
//
// Use errors.As to detect ParseError returned by adapter ParseRequest
// methods:
//
//	_, err := adapter.ParseRequest(ctx, raw)
//	var pe *governance.ParseError
//	if errors.As(err, &pe) {
//	    // adapter-level parse failure; pe.Transport identifies which transport
//	}
type ParseError struct {
	// Transport identifies which adapter failed to parse its input.
	Transport TransportType
	// Reason is a short, human-readable cause (e.g., "empty command",
	// "unsupported raw type int"). Stable enough to match in tests.
	Reason string
	// Err is the underlying cause (e.g., a json.Unmarshal error). May be nil
	// when the failure is purely a validation mismatch with no wrapped error.
	Err error
}

// Error formats the parse error. Stable format:
//   "<transport>: <reason>"           when Err == nil
//   "<transport>: <reason>: <cause>"  when Err != nil
func (e *ParseError) Error() string {
	if e == nil {
		return "<nil *ParseError>"
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Transport, e.Reason, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Transport, e.Reason)
}

// Unwrap returns the underlying cause so errors.Is/As traversal works.
func (e *ParseError) Unwrap() error { return e.Err }

// NewParseError constructs a ParseError. Reason should be a short,
// human-readable cause; err may be nil for pure validation failures.
func NewParseError(transport TransportType, reason string, err error) *ParseError {
	return &ParseError{Transport: transport, Reason: reason, Err: err}
}

// IsParseError reports whether err (or any wrapped error) is a *ParseError.
// It is shorthand for:
//
//	var pe *governance.ParseError
//	errors.As(err, &pe)
func IsParseError(err error) bool {
	var pe *ParseError
	return errors.As(err, &pe)
}
