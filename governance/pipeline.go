package governance

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/google/uuid"

	"github.com/fulcrum-governance/gil/policyeval"
)

// DefaultFailClosedTransports enumerates the transports that fail-closed on
// PolicyEval errors out of the box. These are the transports where silently
// allowing an ungoverned action has real security consequences:
//
//   - TransportMCP — model-facing tool surface; the primary governance wedge.
//   - TransportCodeExec — arbitrary code execution.
//   - TransportGRPC — internal service surface for control-plane calls.
//
// Operators who want different defaults must set
// PipelineConfig.FailClosedTransports explicitly. An explicit (non-nil) empty
// slice opts out of every transport being fail-closed.
var DefaultFailClosedTransports = []TransportType{
	TransportMCP,
	TransportCodeExec,
	TransportGRPC,
}

// PipelineConfig holds configuration for the governance pipeline.
type PipelineConfig struct {
	// StaticPolicies are simple allow/deny rules evaluated before the full engine.
	StaticPolicies []StaticPolicyRule

	// FailClosedTransports are transports that deny on pipeline errors.
	// All other transports fail-open on pipeline errors.
	//
	// Semantics:
	//   - nil (field unset) → DefaultFailClosedTransports is applied.
	//   - non-nil empty slice → all transports fail-open (operator opt-out).
	//   - non-nil populated slice → only the listed transports fail-closed.
	FailClosedTransports []TransportType

	// DryRun enables audit-only mode. When true, any decision that would
	// otherwise deny is converted to allow before Evaluate returns, with
	// GovernanceDecision.DryRun set to true and the original action recorded
	// in the decision reason. The audit event is emitted with the ORIGINAL
	// deny action, so logs reflect what governance would have blocked.
	DryRun bool
}

// PolicyEvaluator is the abstract dependency the pipeline has on the policy
// evaluation engine. The concrete *policyeval.Evaluator in this repo
// satisfies it; tests and alternate implementations can substitute any type
// with the same method.
//
// Keeping this as an interface (rather than a concrete type) is what makes
// the fail-closed-vs-fail-open branch in Evaluate reachable from tests — a
// stub evaluator can return a synthetic error that the stock evaluator
// cannot produce.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, req *policyeval.EvaluationRequest) (*policyeval.Decision, error)
}

// Pipeline evaluates governance requests against trust state, static policies,
// domain interceptors, and the portable policy evaluator.
//
// This is the shared core of the GIL — all transport adapters call Pipeline.Evaluate().
type Pipeline struct {
	trustChecker   TrustChecker
	interceptors   *InterceptorRegistry
	evaluator      PolicyEvaluator
	auditor        AuditPublisher
	staticPolicies []StaticPolicyRule
	failClosed     map[TransportType]bool
	dryRun         bool
}

// NewPipeline creates a governance pipeline.
// All parameters are optional — pass nil for components that are not available.
func NewPipeline(cfg PipelineConfig, trust TrustChecker, evaluator PolicyEvaluator, auditor AuditPublisher) *Pipeline {
	if auditor == nil {
		auditor = noopAuditPublisher{}
	}
	if evaluator == nil {
		evaluator = policyeval.NewEvaluator(nil)
	}

	// nil FailClosedTransports → apply the kernel's secure-by-default list.
	// Non-nil (including explicit empty slice) is taken verbatim.
	failClosedList := cfg.FailClosedTransports
	if failClosedList == nil {
		failClosedList = DefaultFailClosedTransports
	}
	fc := make(map[TransportType]bool, len(failClosedList))
	for _, t := range failClosedList {
		fc[t] = true
	}

	return &Pipeline{
		trustChecker:   trust,
		interceptors:   NewInterceptorRegistry(),
		evaluator:      evaluator,
		auditor:        auditor,
		staticPolicies: cfg.StaticPolicies,
		failClosed:     fc,
		dryRun:         cfg.DryRun,
	}
}

// RegisterInterceptor adds a domain-specific interceptor for a tool name.
func (p *Pipeline) RegisterInterceptor(toolName string, fn Interceptor) {
	p.interceptors.Register(toolName, fn)
}

// toolMatches reports whether a static policy pattern matches a tool name.
// Empty pattern and "*" match everything; otherwise exact match is tried
// first, then path.Match for glob syntax ("*", "?", "[abc]"). Malformed
// patterns are treated as non-matching rather than crashing the pipeline.
func toolMatches(pattern, toolName string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == toolName {
		return true
	}
	matched, _ := path.Match(pattern, toolName)
	return matched
}

// Evaluate runs the full governance pipeline for a request.
//
// The four stages mirror the existing securemcp.GovernancePipeline:
//  1. Trust Check (Redis IPC bridge)
//  2. Static Policy Rules
//  3. Domain Interceptors
//  4. PolicyEval Engine
//
// Audit is emitted exactly once per call via a deferred hook. Dry-run
// conversion happens AFTER audit so logs always reflect the real decision.
func (p *Pipeline) Evaluate(ctx context.Context, req *GovernanceRequest) (*GovernanceDecision, error) {
	start := time.Now()

	if req.EnvelopeID == "" {
		req.EnvelopeID = uuid.New().String()
	}
	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	decision := &GovernanceDecision{
		RequestID:  req.RequestID,
		Action:     "allow",
		TrustScore: 1.0,
		EnvelopeID: req.EnvelopeID,
	}

	defer func() {
		decision.Duration = time.Since(start)
		p.emitAudit(ctx, req, decision)
		if p.dryRun && decision.Action == "deny" {
			original := decision.Reason
			if original == "" {
				original = "(no reason)"
			}
			decision.DryRun = true
			decision.Reason = "DRY-RUN would deny: " + original
			decision.Action = "allow"
		}
	}()

	// Stage 1: Trust Check
	if p.trustChecker != nil && req.AgentID != "" {
		state, err := p.trustChecker.CheckAgentState(ctx, req.AgentID)
		if err != nil {
			decision.Action = "deny"
			decision.Reason = fmt.Sprintf("trust check failed: %v", err)
			decision.TrustScore = 0.0
			return decision, nil
		}
		if state.Blocked() {
			decision.Action = "deny"
			decision.Reason = fmt.Sprintf("agent %s is %s", req.AgentID, state)
			decision.TrustScore = 0.0
			return decision, nil
		}
		if state == TrustStateEvaluating {
			decision.TrustScore = 0.5
		}
	}

	// Stage 2: Static Policy Rules (glob-aware tool match)
	for _, rule := range p.staticPolicies {
		if !toolMatches(rule.Tool, req.ToolName) {
			continue
		}
		if rule.Action == "deny" {
			decision.Action = "deny"
			decision.Reason = rule.Reason
			if decision.Reason == "" {
				decision.Reason = fmt.Sprintf("denied by policy %q", rule.Name)
			}
			return decision, nil
		}
	}

	// Stage 3: Domain Interceptors
	interceptResult, err := p.interceptors.Run(ctx, req)
	if err != nil {
		decision.Action = "deny"
		decision.Reason = fmt.Sprintf("interceptor error: %v", err)
		return decision, nil
	}
	if interceptResult != nil && !interceptResult.Allowed {
		decision.Action = interceptResult.Action
		if decision.Action == "" {
			decision.Action = "deny"
		}
		decision.Reason = interceptResult.Reason
		return decision, nil
	}

	// Stage 4: PolicyEval Engine
	evalReq := &policyeval.EvaluationRequest{
		TenantID:  req.TenantID,
		ToolNames: []string{req.ToolName},
	}
	evalDecision, err := p.evaluator.Evaluate(ctx, evalReq)
	if err != nil {
		if p.failClosed[req.Transport] {
			decision.Action = "deny"
			decision.Reason = fmt.Sprintf("policy evaluation failed (fail-closed): %v", err)
		}
		// fail-open transports: allow proceeds with logged warning
		return decision, nil
	}
	if evalDecision != nil {
		switch evalDecision.Action {
		case policyeval.ActionDeny:
			decision.Action = "deny"
			decision.Reason = evalDecision.Reason
		case policyeval.ActionEscalate:
			decision.Action = "escalate"
			decision.Reason = evalDecision.EscalationReason
		case policyeval.ActionRequireApproval:
			decision.Action = "require_approval"
			decision.Reason = evalDecision.Reason
		case policyeval.ActionWarn:
			decision.Action = "warn"
			decision.Reason = evalDecision.Reason
		}
		if evalDecision.MatchedPolicy != nil {
			decision.PolicyID = evalDecision.MatchedPolicy.PolicyId
		}
	}

	return decision, nil
}

func (p *Pipeline) emitAudit(ctx context.Context, req *GovernanceRequest, decision *GovernanceDecision) {
	p.auditor.Publish(ctx, AuditEvent{
		RequestID:    req.RequestID,
		Transport:    req.Transport,
		ToolName:     req.ToolName,
		Action:       decision.Action,
		Reason:       decision.Reason,
		TrustScore:   decision.TrustScore,
		EnvelopeID:   decision.EnvelopeID,
		AgentID:      req.AgentID,
		TenantID:     req.TenantID,
		Timestamp:    time.Now(),
		DecisionMode: decision.DecisionMode,
	})
}
