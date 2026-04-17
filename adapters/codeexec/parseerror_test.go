package codeexec

import (
	"context"
	"errors"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func TestParseRequest_MissingCode_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), &CodeExecInput{Language: "python"})
	if err == nil {
		t.Fatal("expected error for missing code")
	}

	var pe *governance.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *governance.ParseError, got %T: %v", err, err)
	}
	if pe.Transport != governance.TransportCodeExec {
		t.Errorf("Transport = %s, want code_exec", pe.Transport)
	}
	if pe.Reason != "code field is required" {
		t.Errorf("Reason = %q, want %q", pe.Reason, "code field is required")
	}
}

func TestParseRequest_MissingLanguage_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), &CodeExecInput{Code: "print(1)"})
	if err == nil {
		t.Fatal("expected error for missing language")
	}
	var pe *governance.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *governance.ParseError, got %T: %v", err, err)
	}
	if pe.Reason != "language field is required" {
		t.Errorf("Reason = %q, want %q", pe.Reason, "language field is required")
	}
}
