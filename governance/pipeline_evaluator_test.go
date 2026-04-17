package governance

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/fulcrum-governance/gil/policyeval"
)

// errorEvaluator is a PolicyEvaluator stub that always returns an error.
// It exercises the fail-closed-vs-fail-open branch in Pipeline.Evaluate
// that the stock *policyeval.Evaluator cannot reach.
type errorEvaluator struct{ err error }

func (e *errorEvaluator) Evaluate(_ context.Context, _ *policyeval.EvaluationRequest) (*policyeval.Decision, error) {
	return nil, e.err
}

// TestPipeline_EvaluatorError_FailClosedTransport_Denies exercises the
// fail-closed branch at pipeline.go:189-193. A transport in the fail-closed
// set must DENY on evaluator error, with a reason that surfaces the
// underlying cause.
func TestPipeline_EvaluatorError_FailClosedTransport_Denies(t *testing.T) {
	ev := &errorEvaluator{err: fmt.Errorf("evaluator unavailable")}
	cfg := PipelineConfig{FailClosedTransports: []TransportType{TransportMCP}}
	p := NewPipeline(cfg, nil, ev, nil)

	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
		TenantID:  "t1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Fatalf("expected deny on evaluator error for fail-closed transport, got %s", d.Action)
	}
	if !strings.Contains(d.Reason, "policy evaluation failed (fail-closed)") {
		t.Errorf("expected reason to surface fail-closed cause, got %q", d.Reason)
	}
	if !strings.Contains(d.Reason, "evaluator unavailable") {
		t.Errorf("expected reason to wrap the underlying error, got %q", d.Reason)
	}
}

// TestPipeline_EvaluatorError_FailOpenTransport_Allows verifies the fail-open
// branch. A transport NOT in the fail-closed set must retain the default
// allow action when the evaluator errors. Reason stays empty — callers
// reading audit logs see the action but no synthetic reason.
func TestPipeline_EvaluatorError_FailOpenTransport_Allows(t *testing.T) {
	ev := &errorEvaluator{err: fmt.Errorf("evaluator unavailable")}
	// Explicit empty slice opts into full fail-open (see Phase 1 semantics).
	cfg := PipelineConfig{FailClosedTransports: []TransportType{}}
	p := NewPipeline(cfg, nil, ev, nil)

	req := &GovernanceRequest{
		ToolName:  "health_check",
		Transport: TransportWebhook,
		TenantID:  "t1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Fatalf("expected allow on evaluator error for fail-open transport, got %s", d.Action)
	}
	if d.Reason != "" {
		t.Errorf("expected empty reason for fail-open path, got %q", d.Reason)
	}
}

// TestPipeline_EvaluatorError_AuditEmittedOnBothPaths confirms that both the
// fail-closed and fail-open branches still emit exactly one audit event —
// the defer hook at pipeline.go:118-130 runs regardless of which branch the
// evaluator error takes.
func TestPipeline_EvaluatorError_AuditEmittedOnBothPaths(t *testing.T) {
	ev := &errorEvaluator{err: fmt.Errorf("evaluator unavailable")}
	auditor := &collectingAuditor{}
	cfg := PipelineConfig{FailClosedTransports: []TransportType{TransportMCP}}
	p := NewPipeline(cfg, nil, ev, auditor)

	// Fail-closed request.
	_, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "a", Transport: TransportMCP, TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fail-open request (Webhook is not in the explicit fail-closed list).
	_, err = p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName: "b", Transport: TransportWebhook, TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := auditor.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 audit events (one per Evaluate), got %d", len(events))
	}
	if events[0].Action != "deny" {
		t.Errorf("fail-closed path: expected audit action deny, got %s", events[0].Action)
	}
	if events[1].Action != "allow" {
		t.Errorf("fail-open path: expected audit action allow, got %s", events[1].Action)
	}
}

// TestPipeline_EvaluatorNil_FallsBackToDefault confirms the NewPipeline
// behavior preserved from before the interface extraction: passing nil
// evaluator installs a default real *policyeval.Evaluator rather than leaving
// the pipeline with a nil evaluator that would panic in Stage 4.
func TestPipeline_EvaluatorNil_FallsBackToDefault(t *testing.T) {
	p := NewPipeline(PipelineConfig{}, nil, nil, nil) // nil evaluator
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
		TenantID:  "t1",
	}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow with default evaluator and no policies, got %s", d.Action)
	}
}

// TestPipeline_ConcreteEvaluator_StillAccepted verifies the interface change
// is backwards-compatible: a concrete *policyeval.Evaluator passed to
// NewPipeline still works because it satisfies PolicyEvaluator.
func TestPipeline_ConcreteEvaluator_StillAccepted(t *testing.T) {
	ev := policyeval.NewEvaluator(nil) // concrete type
	p := NewPipeline(PipelineConfig{}, nil, ev, nil)
	req := &GovernanceRequest{
		ToolName:  "read_file",
		Transport: TransportMCP,
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
