package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func TestParseRequest_EmptyCommand_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), &CommandInput{Command: ""})
	if err == nil {
		t.Fatal("expected error for empty command")
	}

	var pe *governance.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *governance.ParseError, got %T: %v", err, err)
	}
	if pe.Transport != governance.TransportCLI {
		t.Errorf("Transport = %s, want cli", pe.Transport)
	}
	if pe.Reason != "empty command" {
		t.Errorf("Reason = %q, want %q", pe.Reason, "empty command")
	}
}

func TestParseRequest_UnsupportedRawType_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), 42)
	if err == nil {
		t.Fatal("expected error for unsupported raw type")
	}
	if !governance.IsParseError(err) {
		t.Errorf("expected IsParseError=true, got err=%v", err)
	}
}
