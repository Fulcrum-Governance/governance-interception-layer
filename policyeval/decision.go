// Package policyeval provides a portable, dependency-free policy evaluation engine.
//
// This package is designed to be embedded in MCP proxies, SDKs, and the main Fulcrum server,
// ensuring consistent policy evaluation behavior across all deployment contexts.
//
// The evaluator operates entirely in-memory with no database, Redis, or NATS dependencies.
// Policies are loaded via UpdatePolicies() and evaluated synchronously.
package policyeval

// ActionType represents the outcome of policy evaluation.
type ActionType int

const (
	// ActionAllow permits the action to proceed.
	ActionAllow ActionType = iota
	// ActionDeny blocks the action.
	ActionDeny
	// ActionEscalate requires a phone-home check (e.g., Semantic Judge).
	ActionEscalate
	// ActionWarn allows but logs a warning.
	ActionWarn
	// ActionRequireApproval requires human approval before proceeding.
	ActionRequireApproval
)

// String returns a human-readable representation of the action type.
func (a ActionType) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionEscalate:
		return "escalate"
	case ActionWarn:
		return "warn"
	case ActionRequireApproval:
		return "require_approval"
	default:
		return "unknown"
	}
}

// Decision represents the result of policy evaluation.
type Decision struct {
	// Action is the primary outcome (allow, deny, escalate, warn, require_approval).
	Action ActionType

	// MatchedPolicy is the policy that produced this decision (if any).
	MatchedPolicy *Policy

	// MatchedRules are the rules within the policy that matched.
	MatchedRules []*RuleMatch

	// Actions are the specific policy actions triggered.
	Actions []*PolicyAction

	// Reason provides a human-readable explanation of the decision.
	Reason string

	// EvaluationDurationMs is how long the evaluation took.
	EvaluationDurationMs int64

	// EscalationReason explains why escalation is needed (only set when Action == ActionEscalate).
	EscalationReason string
}

// RuleMatch represents a matched rule within a policy.
type RuleMatch struct {
	RuleID   string
	RuleName string
	Priority int32
}

// EvaluationRequest contains the context for policy evaluation.
type EvaluationRequest struct {
	// TenantID is the tenant making the request.
	TenantID string

	// UserID is the user or agent making the request.
	UserID string

	// UserRoles are the roles assigned to the user.
	UserRoles []string

	// WorkflowID is the workflow context (if any).
	WorkflowID string

	// EnvelopeID is the envelope being evaluated.
	EnvelopeID string

	// Phase is the execution phase (PRE, MID, POST).
	Phase ExecutionPhase

	// ModelID is the LLM model being used.
	ModelID string

	// ToolNames are the tools being invoked.
	ToolNames []string

	// InputText is the input being processed (for content policies).
	InputText string

	// OutputText is the output being generated (for content policies).
	OutputText string

	// Attributes are custom key-value pairs for condition matching.
	Attributes map[string]string
}

// ToProtoContext converts an EvaluationRequest to the protobuf EvaluationContext.
func (r *EvaluationRequest) ToProtoContext() *EvaluationContext {
	return &EvaluationContext{
		TenantId:   r.TenantID,
		UserId:     r.UserID,
		UserRoles:  r.UserRoles,
		WorkflowId: r.WorkflowID,
		EnvelopeId: r.EnvelopeID,
		Phase:      r.Phase,
		ModelId:    r.ModelID,
		ToolNames:  r.ToolNames,
		InputText:  r.InputText,
		OutputText: r.OutputText,
		Attributes: r.Attributes,
	}
}

// FromProtoContext creates an EvaluationRequest from a protobuf EvaluationContext.
func FromProtoContext(ctx *EvaluationContext) *EvaluationRequest {
	if ctx == nil {
		return &EvaluationRequest{}
	}
	return &EvaluationRequest{
		TenantID:   ctx.TenantId,
		UserID:     ctx.UserId,
		UserRoles:  ctx.UserRoles,
		WorkflowID: ctx.WorkflowId,
		EnvelopeID: ctx.EnvelopeId,
		Phase:      ctx.Phase,
		ModelID:    ctx.ModelId,
		ToolNames:  ctx.ToolNames,
		InputText:  ctx.InputText,
		OutputText: ctx.OutputText,
		Attributes: ctx.Attributes,
	}
}
