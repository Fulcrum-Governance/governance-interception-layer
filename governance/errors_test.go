package governance

import (
	"errors"
	"fmt"
	"testing"
)

func TestParseError_ErrorFormat_WithCause(t *testing.T) {
	pe := &ParseError{
		Transport: TransportMCP,
		Reason:    "unsupported raw type",
		Err:       fmt.Errorf("got int"),
	}
	want := "mcp: unsupported raw type: got int"
	if got := pe.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestParseError_ErrorFormat_WithoutCause(t *testing.T) {
	pe := &ParseError{Transport: TransportCLI, Reason: "empty command"}
	want := "cli: empty command"
	if got := pe.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestParseError_UnwrapExposesCause(t *testing.T) {
	cause := fmt.Errorf("underlying")
	pe := &ParseError{Transport: TransportCodeExec, Reason: "bad input", Err: cause}
	if got := errors.Unwrap(pe); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
}

func TestIsParseError_DetectsWrapped(t *testing.T) {
	pe := NewParseError(TransportWebhook, "bad body", nil)
	wrapped := fmt.Errorf("handler: %w", pe)

	if !IsParseError(pe) {
		t.Error("IsParseError must recognize a bare ParseError")
	}
	if !IsParseError(wrapped) {
		t.Error("IsParseError must recognize a wrapped ParseError")
	}
	if IsParseError(fmt.Errorf("not a parse error")) {
		t.Error("IsParseError must not match unrelated errors")
	}
	if IsParseError(nil) {
		t.Error("IsParseError(nil) must return false")
	}
}

func TestIsParseError_AsExtractsTransport(t *testing.T) {
	pe := NewParseError(TransportA2A, "Action required", nil)
	wrapped := fmt.Errorf("outer: %w", pe)

	var got *ParseError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As must extract *ParseError from wrapped error")
	}
	if got.Transport != TransportA2A {
		t.Errorf("Transport = %s, want a2a", got.Transport)
	}
	if got.Reason != "Action required" {
		t.Errorf("Reason = %q, want %q", got.Reason, "Action required")
	}
}
