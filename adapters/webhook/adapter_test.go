package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

func newPipeline(t *testing.T, deny bool, denyTool string) *governance.Pipeline {
	t.Helper()
	cfg := governance.PipelineConfig{}
	if deny {
		cfg.StaticPolicies = []governance.StaticPolicyRule{{
			Name:   "deny-test",
			Tool:   denyTool,
			Action: "deny",
			Reason: "blocked by test policy",
		}}
	}
	return governance.NewPipeline(cfg, nil, nil, nil)
}

func TestAdapter_Type(t *testing.T) {
	if NewAdapter("").Type() != governance.TransportWebhook {
		t.Fatal("Type should be TransportWebhook")
	}
}

func TestAdapter_ParseRequest_FromPayload(t *testing.T) {
	a := NewAdapter("default-tenant")
	p := &WebhookPayload{
		Tool:      "send_email",
		Arguments: map[string]any{"to": "ceo@x.com"},
		AgentID:   "agent-1",
		TenantID:  "explicit-tenant",
		TraceID:   "trace-99",
	}
	req, err := a.ParseRequest(context.Background(), p)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.ToolName != "send_email" {
		t.Errorf("ToolName = %q", req.ToolName)
	}
	if req.AgentID != "agent-1" || req.TenantID != "explicit-tenant" || req.TraceID != "trace-99" {
		t.Errorf("identity not propagated: %+v", req)
	}
	if req.Transport != governance.TransportWebhook {
		t.Errorf("transport = %s", req.Transport)
	}
}

func TestAdapter_ParseRequest_TenantFallback(t *testing.T) {
	a := NewAdapter("default-tenant")
	req, err := a.ParseRequest(context.Background(), &WebhookPayload{Tool: "x"})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.TenantID != "default-tenant" {
		t.Errorf("expected fallback tenant, got %q", req.TenantID)
	}
}

func TestAdapter_ParseRequest_FromBytes(t *testing.T) {
	a := NewAdapter("t")
	body, _ := json.Marshal(WebhookPayload{Tool: "x", AgentID: "a"})
	req, err := a.ParseRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.ToolName != "x" || req.AgentID != "a" {
		t.Fatalf("bytes path failed: %+v", req)
	}
}

func TestAdapter_ParseRequest_FromHTTPRequest(t *testing.T) {
	a := NewAdapter("t")
	body, _ := json.Marshal(WebhookPayload{Tool: "search", AgentID: "ag"})
	r := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	req, err := a.ParseRequest(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.ToolName != "search" {
		t.Fatalf("http.Request path failed: %+v", req)
	}
	// Body should be restored for downstream readers.
	leftover, _ := io.ReadAll(r.Body)
	if !bytes.Equal(leftover, body) {
		t.Fatalf("request body not restored after parse")
	}
}

func TestAdapter_ParseRequest_Errors(t *testing.T) {
	a := NewAdapter("")
	if _, err := a.ParseRequest(context.Background(), 42); err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if _, err := a.ParseRequest(context.Background(), []byte("{not-json")); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if _, err := a.ParseRequest(context.Background(), &WebhookPayload{}); err == nil {
		t.Fatal("expected error for missing tool")
	}
}

func TestHandler_Allowed_NoForward(t *testing.T) {
	pipe := newPipeline(t, false, "")
	h := Handler(pipe, "")

	body, _ := json.Marshal(WebhookPayload{Tool: "noop", AgentID: "a", TenantID: "t"})
	r := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Governance-Action"); got != "allow" {
		t.Fatalf("expected allow header, got %q", got)
	}
	var d governance.GovernanceDecision
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if d.Action != "allow" {
		t.Fatalf("decision body action = %q", d.Action)
	}
}

func TestHandler_Denied_Returns403(t *testing.T) {
	pipe := newPipeline(t, true, "drop_table")
	h := Handler(pipe, "")

	body, _ := json.Marshal(WebhookPayload{Tool: "drop_table", AgentID: "a", TenantID: "t"})
	r := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Governance-Action"); got != "deny" {
		t.Fatalf("expected deny header, got %q", got)
	}
	if !strings.Contains(w.Header().Get("X-Governance-Reason"), "blocked by test policy") {
		t.Fatalf("missing reason header: %v", w.Header())
	}
}

func TestHandler_BadJSON_Returns400(t *testing.T) {
	pipe := newPipeline(t, false, "")
	h := Handler(pipe, "")
	r := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader("{not-json"))
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandler_MissingTool_Returns400(t *testing.T) {
	pipe := newPipeline(t, false, "")
	h := Handler(pipe, "")
	body, _ := json.Marshal(WebhookPayload{AgentID: "a"})
	r := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandler_ForwardURL_AllowsForward(t *testing.T) {
	// Downstream service that echoes the body.
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Downstream", "yes")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("downstream-saw:" + string(body)))
	}))
	defer downstream.Close()

	pipe := newPipeline(t, false, "")
	h := Handler(pipe, downstream.URL)

	body, _ := json.Marshal(WebhookPayload{Tool: "noop", AgentID: "a", TenantID: "t"})
	r := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 from downstream pass-through, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "downstream-saw:") {
		t.Fatalf("downstream did not see forwarded body: %s", w.Body.String())
	}
	if got := w.Header().Get("X-Governance-Action"); got != "allow" {
		t.Fatalf("expected allow header on forward path, got %q", got)
	}
}

func TestAdapter_NoOpMethods(t *testing.T) {
	a := NewAdapter("")
	if resp, err := a.ForwardGoverned(context.Background(), nil, nil); resp != nil || err != nil {
		t.Errorf("ForwardGoverned should be no-op")
	}
	if insp, err := a.InspectResponse(context.Background(), nil); err != nil || insp == nil {
		t.Errorf("InspectResponse should return benign result")
	}
	if err := a.EmitGovernanceMetadata(context.Background(), nil, nil); err != nil {
		t.Errorf("EmitGovernanceMetadata: %v", err)
	}
}
