package governance

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fulcrum-governance/gil/policyeval"
)

func TestMiddleware_DenyReturns403WithJSON(t *testing.T) {
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	mw := NewMiddleware(p, nil, MiddlewareConfig{})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Tool-Name", "rm")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["action"] != "deny" {
		t.Errorf("expected action=deny, got %q", body["action"])
	}
	if body["reason"] != "destructive" {
		t.Errorf("expected reason=destructive, got %q", body["reason"])
	}
	if body["request_id"] == "" {
		t.Error("expected request_id in response")
	}
	if rec.Header().Get(HeaderGovernanceAction) != "deny" {
		t.Errorf("expected X-Governance-Action header set on deny")
	}
}

func TestMiddleware_AllowForwardsToNext(t *testing.T) {
	var called atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("downstream"))
	})

	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	mw := NewMiddleware(p, next, MiddlewareConfig{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Tool-Name", "read_file")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if !called.Load() {
		t.Error("expected downstream handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get(HeaderGovernanceAction); got != "allow" {
		t.Errorf("expected X-Governance-Action=allow, got %q", got)
	}
	if got := rec.Header().Get(HeaderGovernanceRequestID); got == "" {
		t.Error("expected X-Governance-Request-ID to be set")
	}
}

func TestMiddleware_NilNextReturnsDecisionJSON(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	mw := NewMiddleware(p, nil, MiddlewareConfig{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Tool-Name", "read_file")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from standalone endpoint, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["action"] != "allow" {
		t.Errorf("expected action=allow, got %v", body["action"])
	}
	if body["envelope_id"] == nil || body["envelope_id"] == "" {
		t.Error("expected envelope_id in standalone response")
	}
}

func TestMiddleware_ToolNameFromPath(t *testing.T) {
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-drop", Tool: "drop_table", Action: "deny"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	mw := NewMiddleware(p, nil, MiddlewareConfig{ToolNameFromPath: true})

	req := httptest.NewRequest(http.MethodPost, "/drop_table", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 when tool name taken from path, got %d", rec.Code)
	}
}

func TestMiddleware_CustomHeaders(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	mw := NewMiddleware(p, nil, MiddlewareConfig{
		ToolNameHeader: "X-Op",
		AgentIDHeader:  "X-Actor",
		TenantIDHeader: "X-Workspace",
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Op", "noop")
	req.Header.Set("X-Actor", "agent-7")
	req.Header.Set("X-Workspace", "workspace-42")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	// Standalone endpoint: body includes action.
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["action"] != "allow" {
		t.Errorf("expected allow, got %v", body["action"])
	}
}

func TestMiddleware_DryRunHeader(t *testing.T) {
	cfg := PipelineConfig{
		DryRun: true,
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	// nil Next → standalone. Dry-run converts deny to allow so we return 200.
	mw := NewMiddleware(p, nil, MiddlewareConfig{})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Tool-Name", "rm")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 under dry-run, got %d", rec.Code)
	}
	if got := rec.Header().Get(HeaderGovernanceDryRun); got != "true" {
		t.Errorf("expected X-Governance-Dry-Run=true, got %q", got)
	}
	if got := rec.Header().Get(HeaderGovernanceAction); got != "allow" {
		t.Errorf("expected X-Governance-Action=allow under dry-run, got %q", got)
	}
}

func TestMiddleware_EscalateDoesNotForward(t *testing.T) {
	var called atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newSemanticEscalatePolicy("p-esc"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	mw := NewMiddleware(p, next, MiddlewareConfig{})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Tool-Name", "send_email")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if called.Load() {
		t.Fatal("downstream handler MUST NOT be called on escalate")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 on escalate, got %d", rec.Code)
	}
	if got := rec.Header().Get(HeaderGovernanceAction); got != "escalate" {
		t.Errorf("expected X-Governance-Action=escalate, got %q", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["action"] != "escalate" {
		t.Errorf("expected body action=escalate, got %q", body["action"])
	}
}

func TestMiddleware_RequireApprovalDoesNotForward(t *testing.T) {
	var called atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newMatchAllPolicy("p-approve", policyeval.PolicyActionType_ACTION_TYPE_REQUIRE_APPROVAL, "needs human"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	mw := NewMiddleware(p, next, MiddlewareConfig{})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Tool-Name", "deploy")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if called.Load() {
		t.Fatal("downstream handler MUST NOT be called on require_approval")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 on require_approval, got %d", rec.Code)
	}
	if got := rec.Header().Get(HeaderGovernanceAction); got != "require_approval" {
		t.Errorf("expected X-Governance-Action=require_approval, got %q", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["action"] != "require_approval" {
		t.Errorf("expected body action=require_approval, got %q", body["action"])
	}
}

func TestMiddleware_ConcurrentRequests(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	mw := NewMiddleware(p, next, MiddlewareConfig{})

	srv := httptest.NewServer(mw)
	defer srv.Close()

	const workers = 10
	const perWorker = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			client := &http.Client{}
			for j := 0; j < perWorker; j++ {
				req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
				req.Header.Set("X-Tool-Name", "read_file")
				resp, err := client.Do(req)
				if err != nil {
					errs <- err
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					errs <- http.ErrNotSupported // placeholder to signal failure
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent request failed: %v", err)
		}
	}
}
