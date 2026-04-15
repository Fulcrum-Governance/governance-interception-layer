package governance

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// mockTrustChecker is a test double for TrustChecker.
type mockTrustChecker struct {
	states map[string]TrustState
	err    error
}

func (m *mockTrustChecker) CheckAgentState(_ context.Context, agentID string) (TrustState, error) {
	if m.err != nil {
		return TrustStateIsolated, m.err
	}
	s, ok := m.states[agentID]
	if !ok {
		return TrustStateTrusted, nil
	}
	return s, nil
}

// collectingAuditor captures audit events for assertions.
type collectingAuditor struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *collectingAuditor) Publish(_ context.Context, e AuditEvent) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}

func (a *collectingAuditor) Events() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEvent, len(a.events))
	copy(out, a.events)
	return out
}

func TestPipeline_AllowByDefault(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow, got %s", d.Action)
	}
	if d.TrustScore != 1.0 {
		t.Errorf("expected trust score 1.0, got %f", d.TrustScore)
	}
	if d.EnvelopeID == "" {
		t.Error("expected envelope ID to be generated")
	}
}

func TestPipeline_TrustDeny_Isolated(t *testing.T) {
	tc := &mockTrustChecker{
		states: map[string]TrustState{"agent-1": TrustStateIsolated},
	}
	p := NewPipeline(PipelineConfig{}, tc, nil, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
		AgentID:   "agent-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny, got %s", d.Action)
	}
	if d.TrustScore != 0.0 {
		t.Errorf("expected trust score 0.0, got %f", d.TrustScore)
	}
}

func TestPipeline_TrustDeny_Terminated(t *testing.T) {
	tc := &mockTrustChecker{
		states: map[string]TrustState{"agent-1": TrustStateTerminated},
	}
	p := NewPipeline(PipelineConfig{}, tc, nil, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportCLI,
		AgentID:   "agent-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny, got %s", d.Action)
	}
}

func TestPipeline_TrustError_FailClosed(t *testing.T) {
	tc := &mockTrustChecker{err: fmt.Errorf("redis down")}
	p := NewPipeline(PipelineConfig{}, tc, nil, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
		AgentID:   "agent-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny on trust error, got %s", d.Action)
	}
}

func TestPipeline_TrustEvaluating_HalfScore(t *testing.T) {
	tc := &mockTrustChecker{
		states: map[string]TrustState{"agent-1": TrustStateEvaluating},
	}
	p := NewPipeline(PipelineConfig{}, tc, nil, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
		AgentID:   "agent-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow for evaluating, got %s", d.Action)
	}
	if d.TrustScore != 0.5 {
		t.Errorf("expected trust score 0.5, got %f", d.TrustScore)
	}
}

func TestPipeline_StaticPolicyDeny(t *testing.T) {
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive command"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	req := &GovernanceRequest{ToolName: "rm", Transport: TransportCLI}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny, got %s", d.Action)
	}
	if d.Reason != "destructive command" {
		t.Errorf("expected reason 'destructive command', got %q", d.Reason)
	}
}

func TestPipeline_StaticPolicy_WildcardDeny(t *testing.T) {
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-all", Tool: "*", Action: "deny", Reason: "maintenance mode"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	req := &GovernanceRequest{ToolName: "any_tool", Transport: TransportMCP}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny via wildcard, got %s", d.Action)
	}
}

func TestPipeline_StaticPolicy_NonMatchingTool(t *testing.T) {
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	req := &GovernanceRequest{ToolName: "ls", Transport: TransportCLI}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow for non-matching tool, got %s", d.Action)
	}
}

func TestPipeline_InterceptorDeny(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	p.RegisterInterceptor("dangerous_tool", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return &InterceptorResult{Allowed: false, Action: "deny", Reason: "interceptor blocked"}, nil
	})

	req := &GovernanceRequest{ToolName: "dangerous_tool", Transport: TransportMCP}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny, got %s", d.Action)
	}
	if d.Reason != "interceptor blocked" {
		t.Errorf("unexpected reason: %s", d.Reason)
	}
}

func TestPipeline_InterceptorError(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	p.RegisterInterceptor("bad_tool", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return nil, fmt.Errorf("interceptor crashed")
	})

	req := &GovernanceRequest{ToolName: "bad_tool", Transport: TransportMCP}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny on interceptor error, got %s", d.Action)
	}
}

func TestPipeline_AuditEventEmitted(t *testing.T) {
	auditor := &collectingAuditor{}
	p := NewPipeline(PipelineConfig{}, nil, nil, auditor)

	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportCLI,
		AgentID:   "agent-1",
		TenantID:  "tenant-1",
	}
	_, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := auditor.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	e := events[0]
	if e.ToolName != "read_file" {
		t.Errorf("expected tool_name read_file, got %s", e.ToolName)
	}
	if e.Transport != TransportCLI {
		t.Errorf("expected transport cli, got %s", e.Transport)
	}
	if e.AgentID != "agent-1" {
		t.Errorf("expected agent_id agent-1, got %s", e.AgentID)
	}
	if e.Action != "allow" {
		t.Errorf("expected action allow, got %s", e.Action)
	}
}

func TestPipeline_EnvelopeIDPreserved(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	req := &GovernanceRequest{
		ToolName:   "read_file",
		Transport:  TransportMCP,
		EnvelopeID: "existing-env-id",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.EnvelopeID != "existing-env-id" {
		t.Errorf("expected preserved envelope ID, got %s", d.EnvelopeID)
	}
}

func TestPipeline_StageOrder_TrustBeforePolicy(t *testing.T) {
	// Trust denies, but static policy would also deny — trust should win
	tc := &mockTrustChecker{
		states: map[string]TrustState{"agent-1": TrustStateTerminated},
	}
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-all", Tool: "*", Action: "deny", Reason: "policy reason"},
		},
	}
	p := NewPipeline(cfg, tc, nil, nil)
	req := &GovernanceRequest{
		ToolName:  "any_tool",
		Transport: TransportMCP,
		AgentID:   "agent-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny, got %s", d.Action)
	}
	// Reason should mention trust, not policy
	if d.Reason == "policy reason" {
		t.Error("trust check should have denied before static policy was evaluated")
	}
}

func TestPipeline_NoAgentID_SkipsTrust(t *testing.T) {
	tc := &mockTrustChecker{err: fmt.Errorf("should not be called")}
	p := NewPipeline(PipelineConfig{}, tc, nil, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
		// No AgentID
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow when no agent ID, got %s", d.Action)
	}
}
