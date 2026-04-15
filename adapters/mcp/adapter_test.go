package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func TestAdapter_Type(t *testing.T) {
	a := NewAdapter("tenant-1")
	if a.Type() != governance.TransportMCP {
		t.Errorf("expected TransportMCP, got %s", a.Type())
	}
}

func TestAdapter_ParseRequest_Struct(t *testing.T) {
	a := NewAdapter("default-tenant")
	input := &ToolCallInput{
		ToolName:  "read_file",
		Arguments: map[string]any{"path": "/etc/hosts"},
		AgentID:   "agent-1",
		TenantID:  "tenant-1",
		TraceID:   "trace-abc",
	}

	req, err := a.ParseRequest(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Transport != governance.TransportMCP {
		t.Errorf("expected TransportMCP, got %s", req.Transport)
	}
	if req.ToolName != "read_file" {
		t.Errorf("expected tool_name read_file, got %s", req.ToolName)
	}
	if req.AgentID != "agent-1" {
		t.Errorf("expected agent_id agent-1, got %s", req.AgentID)
	}
	if req.TenantID != "tenant-1" {
		t.Errorf("expected tenant_id tenant-1, got %s", req.TenantID)
	}
	if req.TraceID != "trace-abc" {
		t.Errorf("expected trace_id trace-abc, got %s", req.TraceID)
	}
	if req.Action != "tools/call" {
		t.Errorf("expected action tools/call, got %s", req.Action)
	}
	if req.RequestID == "" {
		t.Error("expected request ID to be generated")
	}
}

func TestAdapter_ParseRequest_DefaultTenant(t *testing.T) {
	a := NewAdapter("default-tenant")
	input := &ToolCallInput{
		ToolName: "list_tools",
	}

	req, err := a.ParseRequest(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.TenantID != "default-tenant" {
		t.Errorf("expected default tenant, got %s", req.TenantID)
	}
}

func TestAdapter_ParseRequest_JSON(t *testing.T) {
	a := NewAdapter("default-tenant")
	data := json.RawMessage(`{"tool_name":"write_file","arguments":{"path":"/tmp/test","content":"hello"},"agent_id":"agent-2"}`)

	req, err := a.ParseRequest(context.Background(), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ToolName != "write_file" {
		t.Errorf("expected tool_name write_file, got %s", req.ToolName)
	}
	if req.AgentID != "agent-2" {
		t.Errorf("expected agent_id agent-2, got %s", req.AgentID)
	}
}

func TestAdapter_ParseRequest_Bytes(t *testing.T) {
	a := NewAdapter("default-tenant")
	data := []byte(`{"tool_name":"query","arguments":{"sql":"SELECT 1"}}`)

	req, err := a.ParseRequest(context.Background(), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ToolName != "query" {
		t.Errorf("expected tool_name query, got %s", req.ToolName)
	}
}

func TestAdapter_ParseRequest_InvalidJSON(t *testing.T) {
	a := NewAdapter("default-tenant")
	data := json.RawMessage(`{invalid json}`)

	_, err := a.ParseRequest(context.Background(), data)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAdapter_ParseRequest_UnsupportedType(t *testing.T) {
	a := NewAdapter("default-tenant")
	_, err := a.ParseRequest(context.Background(), 42)
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestAdapter_InspectResponse_Nil(t *testing.T) {
	a := NewAdapter("default-tenant")
	insp, err := a.InspectResponse(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !insp.Safe {
		t.Error("expected safe=true for nil response")
	}
}

func TestAdapter_EmitGovernanceMetadata(t *testing.T) {
	a := NewAdapter("default-tenant")
	resp := &governance.ToolResponse{Content: []byte("ok")}
	decision := &governance.GovernanceDecision{
		Action:     "allow",
		EnvelopeID: "env-1",
		RequestID:  "req-1",
	}

	err := a.EmitGovernanceMetadata(context.Background(), resp, decision)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Metadata["x-fulcrum-action"] != "allow" {
		t.Errorf("expected x-fulcrum-action=allow, got %s", resp.Metadata["x-fulcrum-action"])
	}
	if resp.Metadata["x-fulcrum-envelope-id"] != "env-1" {
		t.Errorf("expected x-fulcrum-envelope-id=env-1, got %s", resp.Metadata["x-fulcrum-envelope-id"])
	}
}

func TestAdapter_EmitGovernanceMetadata_NilInputs(t *testing.T) {
	a := NewAdapter("default-tenant")
	if err := a.EmitGovernanceMetadata(context.Background(), nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Verify Adapter implements governance.TransportAdapter at compile time.
var _ governance.TransportAdapter = (*Adapter)(nil)
