package governance

import (
	"context"
	"sync"
	"testing"

	"github.com/fulcrum-governance/gil/policyeval"
)

// newMatchAllPolicy builds a policy whose single rule has no conditions
// (matches every context) and terminates with the given action. Used to drive
// the PolicyEval stage in pipeline tests deterministically.
func newMatchAllPolicy(id string, action policyeval.PolicyActionType, msg string) *policyeval.Policy {
	return &policyeval.Policy{
		PolicyId: id,
		TenantId: "tenant-1",
		Name:     "match-all-" + id,
		Status:   policyeval.PolicyStatus_POLICY_STATUS_ACTIVE,
		Priority: 1,
		Scope:    &policyeval.PolicyScope{ApplyToAll: true},
		Rules: []*policyeval.PolicyRule{{
			RuleId:  "r1",
			Name:    "rule1",
			Enabled: true,
			Actions: []*policyeval.PolicyAction{{
				ActionType: action,
				Message:    msg,
				Terminal:   true,
			}},
		}},
	}
}

// newSemanticEscalatePolicy builds a policy whose rule contains a semantic
// condition. The evaluator escalates on semantic conditions rather than
// evaluating them locally.
func newSemanticEscalatePolicy(id string) *policyeval.Policy {
	return &policyeval.Policy{
		PolicyId: id,
		TenantId: "tenant-1",
		Name:     "semantic-" + id,
		Status:   policyeval.PolicyStatus_POLICY_STATUS_ACTIVE,
		Priority: 1,
		Scope:    &policyeval.PolicyScope{ApplyToAll: true},
		Rules: []*policyeval.PolicyRule{{
			RuleId:  "r1",
			Name:    "semantic-rule",
			Enabled: true,
			Conditions: []*policyeval.PolicyCondition{{
				ConditionType:  policyeval.ConditionType_CONDITION_TYPE_SEMANTIC,
				SemanticIntent: "detect-exfiltration",
			}},
			Actions: []*policyeval.PolicyAction{{
				ActionType: policyeval.PolicyActionType_ACTION_TYPE_DENY,
				Terminal:   true,
			}},
		}},
	}
}

func TestPipeline_PolicyEval_Deny(t *testing.T) {
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newMatchAllPolicy("p1", policyeval.PolicyActionType_ACTION_TYPE_DENY, "policy denied"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
		TenantID:  "tenant-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny from policyeval, got %s", d.Action)
	}
	if d.PolicyID != "p1" {
		t.Errorf("expected matched policy id p1, got %q", d.PolicyID)
	}
}

func TestPipeline_PolicyEval_Warn(t *testing.T) {
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newMatchAllPolicy("p-warn", policyeval.PolicyActionType_ACTION_TYPE_WARN, "noisy tool"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	req := &GovernanceRequest{
		ToolName:  "loud_tool",
		Transport: TransportCLI,
		TenantID:  "tenant-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "warn" {
		t.Errorf("expected warn, got %s", d.Action)
	}
	if d.PolicyID != "p-warn" {
		t.Errorf("expected policy id p-warn, got %q", d.PolicyID)
	}
}

func TestPipeline_PolicyEval_RequireApproval(t *testing.T) {
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newMatchAllPolicy("p-approve", policyeval.PolicyActionType_ACTION_TYPE_REQUIRE_APPROVAL, "needs human"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	req := &GovernanceRequest{
		ToolName:  "deploy",
		Transport: TransportMCP,
		TenantID:  "tenant-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "require_approval" {
		t.Errorf("expected require_approval, got %s", d.Action)
	}
}

func TestPipeline_PolicyEval_Escalate(t *testing.T) {
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newSemanticEscalatePolicy("p-esc"),
	})
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	req := &GovernanceRequest{
		ToolName:  "send_email",
		Transport: TransportMCP,
		TenantID:  "tenant-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "escalate" {
		t.Errorf("expected escalate for semantic condition, got %s", d.Action)
	}
	if d.Reason == "" {
		t.Error("expected escalation reason to be populated")
	}
}

func TestPipeline_InterceptorEmptyAction_DefaultsDeny(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	// Interceptor returns Allowed=false but leaves Action blank — pipeline
	// must default to "deny".
	p.RegisterInterceptor("ambiguous_tool", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return &InterceptorResult{Allowed: false, Action: "", Reason: "unspecified"}, nil
	})
	req := &GovernanceRequest{ToolName: "ambiguous_tool", Transport: TransportMCP}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected empty interceptor action to default to deny, got %s", d.Action)
	}
}

func TestPipeline_FailClosedTransports_BuildsMap(t *testing.T) {
	// Configure a pipeline with FailClosedTransports populated to exercise
	// the map-building loop in NewPipeline. Behavioral effects of fail-closed
	// on Evaluator errors are unreachable because *policyeval.Evaluator never
	// returns an error for non-nil requests; we just verify the pipeline
	// evaluates a normal request successfully when the map is populated.
	cfg := PipelineConfig{
		FailClosedTransports: []TransportType{TransportMCP, TransportCodeExec},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	if !p.failClosed[TransportMCP] {
		t.Error("expected TransportMCP to be marked fail-closed")
	}
	if !p.failClosed[TransportCodeExec] {
		t.Error("expected TransportCodeExec to be marked fail-closed")
	}
	if p.failClosed[TransportCLI] {
		t.Error("expected TransportCLI to NOT be marked fail-closed")
	}

	req := &GovernanceRequest{ToolName: "read_file", Transport: TransportMCP, TenantID: "t1"}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow-by-default even with fail-closed config, got %s", d.Action)
	}
}

func TestPipeline_NilTrustChecker_WithAgentID(t *testing.T) {
	// When trustChecker is nil, the trust stage must be skipped even when
	// the request carries an AgentID.
	p := NewPipeline(PipelineConfig{}, nil, nil, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
		AgentID:   "agent-present",
		TenantID:  "tenant-1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow when trust checker is nil, got %s", d.Action)
	}
	if d.TrustScore != 1.0 {
		t.Errorf("expected trust score 1.0 when trust stage skipped, got %f", d.TrustScore)
	}
}

func TestPipeline_ConcurrentEvaluate(t *testing.T) {
	// Exercise the pipeline from many goroutines to confirm no shared state
	// is mutated unsafely. Run with -race to catch data races.
	auditor := &collectingAuditor{}
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	tc := &mockTrustChecker{
		states: map[string]TrustState{"agent-bad": TrustStateIsolated},
	}
	ev := policyeval.NewEvaluator([]*policyeval.Policy{
		newMatchAllPolicy("p-warn", policyeval.PolicyActionType_ACTION_TYPE_WARN, "loud"),
	})
	p := NewPipeline(cfg, tc, ev, auditor)

	const goroutines = 50
	const perGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				req := &GovernanceRequest{
					ToolName:  "read_file",
					Transport: TransportMCP,
					AgentID:   "agent-good",
					TenantID:  "tenant-1",
				}
				if _, err := p.Evaluate(context.Background(), req); err != nil {
					t.Errorf("goroutine %d iteration %d: %v", id, j, err)
				}
			}
		}(i)
	}
	wg.Wait()

	if got := len(auditor.Events()); got != goroutines*perGoroutine {
		t.Errorf("expected %d audit events, got %d", goroutines*perGoroutine, got)
	}
}

func TestPipeline_EmptyStaticPolicyList_NoMatch(t *testing.T) {
	// Explicitly verify the Stage 2 loop with a zero-length slice is safe and
	// does not change the allow-by-default outcome.
	cfg := PipelineConfig{StaticPolicies: []StaticPolicyRule{}}
	p := NewPipeline(cfg, nil, nil, nil)
	req := &GovernanceRequest{ToolName: "any", Transport: TransportCLI}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow with empty static policies, got %s", d.Action)
	}
}

func TestPipeline_AuditPublisher_NoopDefault(t *testing.T) {
	// Passing nil auditor should fall back to noopAuditPublisher and not panic
	// across a full evaluation that touches all four stages.
	tc := &mockTrustChecker{states: map[string]TrustState{"a": TrustStateTrusted}}
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "r"},
		},
	}
	p := NewPipeline(cfg, tc, nil, nil) // nil auditor
	p.RegisterInterceptor("inspect", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return nil, nil // no interception
	})
	req := &GovernanceRequest{
		ToolName:  "inspect",
		Transport: TransportMCP,
		AgentID:   "a",
		TenantID:  "t1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow, got %s", d.Action)
	}
}

// noopPublisherInvoke directly invokes the unexported noopAuditPublisher to
// register coverage on its empty Publish body (declared in audit.go).
func TestNoopAuditPublisher_Publish(t *testing.T) {
	var pub AuditPublisher = noopAuditPublisher{}
	// Must not panic and must not block.
	pub.Publish(context.Background(), AuditEvent{RequestID: "r-1"})
}
