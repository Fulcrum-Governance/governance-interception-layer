package webhook

import (
	"context"
	"errors"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func TestParseRequest_MissingTool_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), &WebhookPayload{Tool: ""})
	if err == nil {
		t.Fatal("expected error for missing tool")
	}

	var pe *governance.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *governance.ParseError, got %T: %v", err, err)
	}
	if pe.Transport != governance.TransportWebhook {
		t.Errorf("Transport = %s, want webhook", pe.Transport)
	}
	if pe.Reason != "tool field is required" {
		t.Errorf("Reason = %q, want %q", pe.Reason, "tool field is required")
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
