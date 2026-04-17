package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func TestParseRequest_UnsupportedRawType_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), "not a *CallInfo")
	if err == nil {
		t.Fatal("expected error for unsupported raw type")
	}

	var pe *governance.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *governance.ParseError, got %T: %v", err, err)
	}
	if pe.Transport != governance.TransportGRPC {
		t.Errorf("Transport = %s, want grpc", pe.Transport)
	}
}

func TestParseRequest_EmptyMethod_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), &CallInfo{Method: ""})
	if err == nil {
		t.Fatal("expected error for empty method")
	}
	var pe *governance.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *governance.ParseError, got %T: %v", err, err)
	}
	if pe.Reason != "CallInfo.Method is required" {
		t.Errorf("Reason = %q, want %q", pe.Reason, "CallInfo.Method is required")
	}
}
