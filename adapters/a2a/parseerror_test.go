package a2a

import (
	"context"
	"errors"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func TestParseRequest_MissingAction_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), &TaskMessage{Action: ""})
	if err == nil {
		t.Fatal("expected error for missing action")
	}

	var pe *governance.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *governance.ParseError, got %T: %v", err, err)
	}
	if pe.Transport != governance.TransportA2A {
		t.Errorf("Transport = %s, want a2a", pe.Transport)
	}
	if pe.Reason != "TaskMessage.Action is required" {
		t.Errorf("Reason = %q, want %q", pe.Reason, "TaskMessage.Action is required")
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
