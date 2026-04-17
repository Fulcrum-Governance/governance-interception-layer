package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/fulcrum-governance/gil/policyeval"
)

// Every test below pins DecisionMode for one of the branches in
// pipeline.go. Phase 3 sets the default to DecisionModeDeterministic and
// overrides to DecisionModeClassified only for PolicyEval ActionEscalate.

func TestPipeline_TrustError_DecisionMode(t *testing.T) {
	tc := &mockTrustChecker{err: fmt.Errorf("redis down")}
	p := NewPipeline(PipelineConfig{}, tc, nil, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "read_file", Transport: TransportMCP, AgentID: "agent-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Fatalf("expected deny, got %s", d.Action)
	}
	if d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("trust-error deny should be deterministic, got %s", d.DecisionMode)
	}
}

func TestPipeline_TrustBlocked_DecisionMode(t *testing.T) {
	tc := &mockTrustChecker{states: map[string]TrustState{"a": TrustStateIsolated}}
	p := NewPipeline(PipelineConfig{}, tc, nil, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "read_file", Transport: TransportMCP, AgentID: "a",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("blocked-agent deny should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

func TestPipeline_StaticPolicyDeny_DecisionMode(t *testing.T) {
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{ToolName: "rm", Transport: TransportCLI})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("static-policy deny should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

func TestPipeline_InterceptorError_DecisionMode(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	p.RegisterInterceptor("bad", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return nil, fmt.Errorf("crashed")
	})
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{ToolName: "bad", Transport: TransportMCP})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("interceptor-error deny should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

func TestPipeline_InterceptorExplicitDeny_DecisionMode(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	p.RegisterInterceptor("danger", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return &InterceptorResult{Allowed: false, Action: "deny", Reason: "blocked"}, nil
	})
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{ToolName: "danger", Transport: TransportMCP})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("interceptor explicit deny should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

func TestPipeline_PolicyEvalDeny_DecisionMode(t *testing.T) {
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newMatchAllPolicy("p-deny", policyeval.PolicyActionType_ACTION_TYPE_DENY, "nope"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "read_file", Transport: TransportMCP, TenantID: "tenant-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("policyeval deny should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

func TestPipeline_PolicyEvalWarn_DecisionMode(t *testing.T) {
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newMatchAllPolicy("p-warn", policyeval.PolicyActionType_ACTION_TYPE_WARN, "loud"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "loud_tool", Transport: TransportCLI, TenantID: "tenant-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "warn" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("policyeval warn should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

func TestPipeline_PolicyEvalRequireApproval_DecisionMode(t *testing.T) {
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newMatchAllPolicy("p-appr", policyeval.PolicyActionType_ACTION_TYPE_REQUIRE_APPROVAL, "needs human"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "deploy", Transport: TransportMCP, TenantID: "tenant-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "require_approval" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("policyeval require_approval should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

func TestPipeline_PolicyEvalEscalate_DecisionMode(t *testing.T) {
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newSemanticEscalatePolicy("p-esc"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "send_email", Transport: TransportMCP, TenantID: "tenant-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "escalate" {
		t.Fatalf("expected escalate, got %s", d.Action)
	}
	if d.DecisionMode != DecisionModeClassified {
		t.Errorf("policyeval escalate should flip to classified, got %s", d.DecisionMode)
	}
}

func TestPipeline_FailClosedEvaluatorError_DecisionMode(t *testing.T) {
	ev := &errorEvaluator{err: fmt.Errorf("evaluator unavailable")}
	cfg := PipelineConfig{FailClosedTransports: []TransportType{TransportMCP}}
	p := NewPipeline(cfg, nil, ev, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "x", Transport: TransportMCP, TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("fail-closed eval error deny should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

func TestPipeline_DefaultAllow_DecisionMode(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	d, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "read_file", Transport: TransportMCP,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" || d.DecisionMode != DecisionModeDeterministic {
		t.Errorf("default allow should be deterministic, got action=%s mode=%s", d.Action, d.DecisionMode)
	}
}

// TestPipeline_Audit_DecisionMode_Propagated confirms the Phase 2 wiring:
// the audit event carries the same DecisionMode as the decision. Runs both
// a deterministic deny and a classified escalate so both codepaths are
// pinned end-to-end.
func TestPipeline_Audit_DecisionMode_Propagated(t *testing.T) {
	auditor := &collectingAuditor{}

	// Deterministic deny via static policy.
	p1 := NewPipeline(PipelineConfig{
		StaticPolicies: []StaticPolicyRule{{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "x"}},
	}, nil, nil, auditor)
	if _, err := p1.Evaluate(context.Background(), &GovernanceRequest{ToolName: "rm", Transport: TransportCLI}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Classified escalate via semantic policy.
	ev := policyeval.NewEvaluator([]*policyeval.Policy{newSemanticEscalatePolicy("p-esc")})
	p2 := NewPipeline(PipelineConfig{}, nil, ev, auditor)
	if _, err := p2.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "send_email", Transport: TransportMCP, TenantID: "tenant-1",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := auditor.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(events))
	}
	if events[0].Action != "deny" || events[0].DecisionMode != DecisionModeDeterministic {
		t.Errorf("event[0]: expected deny/deterministic, got %s/%s", events[0].Action, events[0].DecisionMode)
	}
	if events[1].Action != "escalate" || events[1].DecisionMode != DecisionModeClassified {
		t.Errorf("event[1]: expected escalate/classified, got %s/%s", events[1].Action, events[1].DecisionMode)
	}
}

// TestGovernanceDecision_DecisionMode_JSONOmitempty anchors the backwards-
// compat contract: a decision with an unset DecisionMode serializes without
// the decision_mode key, so existing consumers that don't know about the
// field see no wire-format change.
func TestGovernanceDecision_DecisionMode_JSONOmitempty(t *testing.T) {
	d := GovernanceDecision{Action: "allow"} // DecisionMode unset
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes := string(b); containsKey(bytes, "decision_mode") {
		t.Errorf("unset DecisionMode must be omitted from JSON; got %s", bytes)
	}

	d.DecisionMode = DecisionModeDeterministic
	b, err = json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes := string(b); !containsKey(bytes, `"decision_mode":"deterministic"`) {
		t.Errorf("set DecisionMode must appear in JSON; got %s", bytes)
	}
}

func containsKey(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
