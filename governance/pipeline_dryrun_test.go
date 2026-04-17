package governance

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestPipeline_DryRun_StaticPolicyDeny_RewrittenToAllow verifies the core
// DryRun contract: a decision that would have denied is rewritten to
// allow before Evaluate returns, with DryRun=true and the original reason
// preserved under a "DRY-RUN would deny:" prefix.
//
// Drives the rewrite branch at pipeline.go:121-129.
func TestPipeline_DryRun_StaticPolicyDeny_RewrittenToAllow(t *testing.T) {
	cfg := PipelineConfig{
		DryRun: true,
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive command"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)

	req := &GovernanceRequest{ToolName: "rm", Transport: TransportCLI, TenantID: "t1"}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("DryRun must rewrite deny to allow for the caller; got %s", d.Action)
	}
	if !d.DryRun {
		t.Error("expected decision.DryRun=true on rewritten decision")
	}
	if !strings.HasPrefix(d.Reason, "DRY-RUN would deny: ") {
		t.Errorf("expected DRY-RUN reason prefix, got %q", d.Reason)
	}
	if !strings.Contains(d.Reason, "destructive command") {
		t.Errorf("expected original reason to be preserved after prefix, got %q", d.Reason)
	}
}

// TestPipeline_DryRun_AuditPreservesOriginalDeny asserts the key audit
// invariant: DryRun rewrites the caller-visible action AFTER the audit hook
// fires, so audit streams always show the real decision. This is what makes
// DryRun safe for pre-rollout evaluation.
//
// Drives the ordering at pipeline.go:118-130 (audit before rewrite).
func TestPipeline_DryRun_AuditPreservesOriginalDeny(t *testing.T) {
	auditor := &collectingAuditor{}
	cfg := PipelineConfig{
		DryRun: true,
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive command"},
		},
	}
	p := NewPipeline(cfg, nil, nil, auditor)

	req := &GovernanceRequest{ToolName: "rm", Transport: TransportCLI, TenantID: "t1"}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Caller-visible action is rewritten.
	if d.Action != "allow" {
		t.Errorf("caller action: expected allow, got %s", d.Action)
	}

	// Audit event must carry the ORIGINAL deny.
	events := auditor.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "deny" {
		t.Errorf("audit must record the real decision; expected deny, got %s", events[0].Action)
	}
	if events[0].Reason != "destructive command" {
		t.Errorf("audit must record the original reason; got %q", events[0].Reason)
	}
}

// TestPipeline_DryRun_AllowDecision_Untouched confirms DryRun does not
// manufacture spurious DryRun=true flags. If the pipeline decides allow on
// its own merits, the decision passes through unchanged.
func TestPipeline_DryRun_AllowDecision_Untouched(t *testing.T) {
	cfg := PipelineConfig{DryRun: true} // DryRun on, no denying policies
	p := NewPipeline(cfg, nil, nil, nil)

	req := &GovernanceRequest{ToolName: "read_file", Transport: TransportMCP, TenantID: "t1"}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow, got %s", d.Action)
	}
	if d.DryRun {
		t.Error("DryRun must not flag genuine allow decisions")
	}
	if strings.HasPrefix(d.Reason, "DRY-RUN") {
		t.Errorf("allow decisions must not carry DRY-RUN reason prefix; got %q", d.Reason)
	}
}

// TestPipeline_DryRun_FailClosedEvaluatorError_Rewritten combines the Phase 2
// evaluator seam with DryRun. A fail-closed transport that would have denied
// on evaluator error must still be rewritten to allow under DryRun, and the
// audit event must record the original deny with the fail-closed reason.
//
// This is the most security-relevant DryRun path: operators enable DryRun
// specifically to quantify what a fail-closed posture would block before
// flipping it on in production.
func TestPipeline_DryRun_FailClosedEvaluatorError_Rewritten(t *testing.T) {
	auditor := &collectingAuditor{}
	ev := &errorEvaluator{err: fmt.Errorf("evaluator unavailable")}
	cfg := PipelineConfig{
		DryRun:               true,
		FailClosedTransports: []TransportType{TransportMCP},
	}
	p := NewPipeline(cfg, nil, ev, auditor)

	req := &GovernanceRequest{ToolName: "read_file", Transport: TransportMCP, TenantID: "t1"}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Caller sees allow.
	if d.Action != "allow" {
		t.Errorf("expected allow for caller under DryRun, got %s", d.Action)
	}
	if !d.DryRun {
		t.Error("expected decision.DryRun=true")
	}
	if !strings.HasPrefix(d.Reason, "DRY-RUN would deny: ") {
		t.Errorf("expected DRY-RUN prefix, got %q", d.Reason)
	}
	if !strings.Contains(d.Reason, "policy evaluation failed (fail-closed)") {
		t.Errorf("expected original fail-closed reason to be preserved; got %q", d.Reason)
	}

	// Audit records the real deny with the real reason.
	events := auditor.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "deny" {
		t.Errorf("audit must record deny; got %s", events[0].Action)
	}
	if !strings.Contains(events[0].Reason, "policy evaluation failed (fail-closed)") {
		t.Errorf("audit must record fail-closed reason; got %q", events[0].Reason)
	}
}
