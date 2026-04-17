package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

// TestParseRequest_UnsupportedRawType_ReturnsParseError pins the typed error
// contract: an unsupported raw input type yields a *governance.ParseError
// whose Transport identifies this adapter.
func TestParseRequest_UnsupportedRawType_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), 42)
	if err == nil {
		t.Fatal("expected error for unsupported raw type")
	}

	var pe *governance.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *governance.ParseError, got %T: %v", err, err)
	}
	if pe.Transport != governance.TransportMCP {
		t.Errorf("Transport = %s, want mcp", pe.Transport)
	}
}

// TestParseRequest_MalformedJSON_ReturnsParseError verifies that unmarshal
// failures also surface as ParseError, with the underlying json error
// preserved via Unwrap.
func TestParseRequest_MalformedJSON_ReturnsParseError(t *testing.T) {
	a := NewAdapter("tenant-1")
	_, err := a.ParseRequest(context.Background(), json.RawMessage(`{not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}

	if !governance.IsParseError(err) {
		t.Fatalf("expected IsParseError=true, got err=%v", err)
	}

	var pe *governance.ParseError
	_ = errors.As(err, &pe)
	if pe.Transport != governance.TransportMCP {
		t.Errorf("Transport = %s, want mcp", pe.Transport)
	}
	if pe.Err == nil {
		t.Error("expected underlying json error to be preserved via Unwrap")
	}
}
