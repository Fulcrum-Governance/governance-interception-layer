package a2a

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func TestAdapter_Type(t *testing.T) {
	if NewAdapter("t").Type() != governance.TransportA2A {
		t.Fatal("Type should be TransportA2A")
	}
}

func TestAdapter_ParseRequest_FromStruct(t *testing.T) {
	a := NewAdapter("tenant-X")
	msg := &TaskMessage{
		TaskID:    "task-123",
		AgentCard: AgentCard{AgentID: "agent-7", Name: "Worker", Endpoint: "https://x"},
		Action:    "execute_query",
		Input:     map[string]any{"query": "SELECT 1"},
	}
	req, err := a.ParseRequest(context.Background(), msg)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.Transport != governance.TransportA2A {
		t.Errorf("transport = %s", req.Transport)
	}
	if req.ToolName != "execute_query" {
		t.Errorf("ToolName = %q, want execute_query", req.ToolName)
	}
	if req.AgentID != "agent-7" {
		t.Errorf("AgentID = %q", req.AgentID)
	}
	if req.TenantID != "tenant-X" {
		t.Errorf("TenantID = %q", req.TenantID)
	}
	if req.TraceID != "task-123" {
		t.Errorf("TraceID = %q", req.TraceID)
	}
	if req.Action != "a2a/task" {
		t.Errorf("Action = %q", req.Action)
	}
	if v, _ := req.Arguments["query"].(string); v != "SELECT 1" {
		t.Errorf("Arguments did not propagate: %+v", req.Arguments)
	}
}

func TestAdapter_ParseRequest_FromValueStruct(t *testing.T) {
	a := NewAdapter("t")
	msg := TaskMessage{Action: "ping", AgentCard: AgentCard{AgentID: "a"}}
	req, err := a.ParseRequest(context.Background(), msg)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.ToolName != "ping" {
		t.Fatal("value-struct path failed")
	}
}

func TestAdapter_ParseRequest_FromJSONBytes(t *testing.T) {
	a := NewAdapter("tenant-Y")
	body, _ := json.Marshal(TaskMessage{
		TaskID:    "t-1",
		AgentCard: AgentCard{AgentID: "agent-9"},
		Action:    "summarize",
		Input:     map[string]any{"doc": "hello"},
	})
	req, err := a.ParseRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.ToolName != "summarize" || req.AgentID != "agent-9" || req.TenantID != "tenant-Y" {
		t.Fatalf("JSON path produced wrong fields: %+v", req)
	}
}

func TestAdapter_ParseRequest_FromRawMessage(t *testing.T) {
	a := NewAdapter("t")
	body := json.RawMessage(`{"action":"x","agent_card":{"agent_id":"a"}}`)
	req, err := a.ParseRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.ToolName != "x" {
		t.Fatal("RawMessage path failed")
	}
}

func TestAdapter_ParseRequest_Errors(t *testing.T) {
	a := NewAdapter("t")
	if _, err := a.ParseRequest(context.Background(), 42); err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if _, err := a.ParseRequest(context.Background(), []byte("{not-json")); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if _, err := a.ParseRequest(context.Background(), &TaskMessage{Action: ""}); err == nil {
		t.Fatal("expected error for missing Action")
	}
}

func TestAdapter_NoOpMethods(t *testing.T) {
	a := NewAdapter("t")
	if resp, err := a.ForwardGoverned(context.Background(), nil, nil); resp != nil || err != nil {
		t.Errorf("ForwardGoverned: expected nil,nil got %v,%v", resp, err)
	}
	if insp, err := a.InspectResponse(context.Background(), nil); insp != nil || err != nil {
		t.Errorf("InspectResponse: expected nil,nil got %v,%v", insp, err)
	}
	if err := a.EmitGovernanceMetadata(context.Background(), nil, nil); err != nil {
		t.Errorf("EmitGovernanceMetadata: %v", err)
	}
}
