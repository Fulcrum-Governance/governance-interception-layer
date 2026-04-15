package policyeval

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Evaluator provides thread-safe policy evaluation with no infrastructure dependencies.
// It is designed to be embedded in MCP proxies, SDKs, and the Fulcrum server.
type Evaluator struct {
	// policies is the in-memory policy set, sorted by priority (highest first).
	policies []*Policy

	// mu protects concurrent access to policies.
	mu sync.RWMutex

	// Configuration
	maxEvaluationTime    time.Duration
	logger               Logger
	externalCallsEnabled bool
	stopOnDeny           bool
}

// NewEvaluator creates a new policy evaluator with the provided policies.
func NewEvaluator(policies []*Policy, opts ...Option) *Evaluator {
	e := &Evaluator{
		maxEvaluationTime:    10 * time.Millisecond,
		logger:               noopLogger{},
		externalCallsEnabled: false,
		stopOnDeny:           true,
	}

	for _, opt := range opts {
		opt(e)
	}

	e.UpdatePolicies(policies)
	return e
}

// UpdatePolicies replaces the policy set with a new set.
// This is used for cache synchronization from the server.
// Policies are sorted by priority (highest first) for correct evaluation order.
func (e *Evaluator) UpdatePolicies(policies []*Policy) {
	// Sort by priority descending (higher priority = evaluated first)
	sorted := make([]*Policy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	e.mu.Lock()
	e.policies = sorted
	e.mu.Unlock()
}

// Policies returns a copy of the current policy set.
func (e *Evaluator) Policies() []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Policy, len(e.policies))
	copy(result, e.policies)
	return result
}

// PolicyCount returns the number of loaded policies.
func (e *Evaluator) PolicyCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.policies)
}

// Evaluate evaluates all applicable policies against the request context.
// Returns a Decision indicating whether the action should be allowed, denied, or escalated.
func (e *Evaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*Decision, error) {
	if req == nil {
		return nil, fmt.Errorf("evaluation request is nil")
	}

	startTime := time.Now()
	evalCtx := req.ToProtoContext()

	e.mu.RLock()
	policies := e.policies
	e.mu.RUnlock()

	var allActions []*PolicyAction
	var matchedRules []*RuleMatch
	var matchedPolicy *Policy
	finalAction := ActionAllow
	var escalationReason string

policyLoop:
	for _, policy := range policies {
		// Skip non-active policies
		if policy.Status != PolicyStatus_POLICY_STATUS_ACTIVE {
			continue
		}

		// Check if policy applies to this context
		if !e.policyApplies(policy, evalCtx) {
			continue
		}

		// Evaluate the policy
		decision, err := e.evaluatePolicy(ctx, policy, evalCtx)
		if err != nil {
			e.logger.Debug("policy evaluation error",
				Field{Key: "policy_id", Value: policy.PolicyId},
				Field{Key: "error", Value: err.Error()})
			continue
		}

		// Collect matched rules and actions
		matchedRules = append(matchedRules, decision.MatchedRules...)
		allActions = append(allActions, decision.Actions...)

		// Update final action based on precedence
		switch decision.Action {
		case ActionDeny:
			finalAction = ActionDeny
			matchedPolicy = policy
			if e.stopOnDeny {
				break policyLoop
			}
		case ActionEscalate:
			if finalAction != ActionDeny {
				finalAction = ActionEscalate
				escalationReason = decision.EscalationReason
				if matchedPolicy == nil {
					matchedPolicy = policy
				}
			}
		case ActionRequireApproval:
			if finalAction != ActionDeny && finalAction != ActionEscalate {
				finalAction = ActionRequireApproval
				if matchedPolicy == nil {
					matchedPolicy = policy
				}
			}
		case ActionWarn:
			if finalAction == ActionAllow {
				finalAction = ActionWarn
				if matchedPolicy == nil {
					matchedPolicy = policy
				}
			}
		}
	}

	duration := time.Since(startTime)

	// Warn if evaluation took too long
	if duration > e.maxEvaluationTime {
		e.logger.Warn("policy evaluation exceeded time limit",
			Field{Key: "duration_ms", Value: duration.Milliseconds()},
			Field{Key: "limit_ms", Value: e.maxEvaluationTime.Milliseconds()})
	}

	reason := fmt.Sprintf("Evaluated %d policies, %d rules matched", len(policies), len(matchedRules))
	if len(matchedRules) == 0 {
		reason = "No rules matched - action allowed by default"
	}

	return &Decision{
		Action:               finalAction,
		MatchedPolicy:        matchedPolicy,
		MatchedRules:         matchedRules,
		Actions:              allActions,
		Reason:               reason,
		EvaluationDurationMs: duration.Milliseconds(),
		EscalationReason:     escalationReason,
	}, nil
}

// EvaluatePolicy evaluates a single policy against the context.
func (e *Evaluator) EvaluatePolicy(ctx context.Context, policy *Policy, req *EvaluationRequest) (*Decision, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("evaluation request is nil")
	}

	return e.evaluatePolicy(ctx, policy, req.ToProtoContext())
}

// evaluatePolicy is the internal implementation.
func (e *Evaluator) evaluatePolicy(ctx context.Context, policy *Policy, evalCtx *EvaluationContext) (*Decision, error) {
	startTime := time.Now()

	// Validate inputs
	if policy.Status != PolicyStatus_POLICY_STATUS_ACTIVE {
		return &Decision{
			Action: ActionAllow,
			Reason: fmt.Sprintf("Policy %s is not active (status: %s)", policy.PolicyId, policy.Status),
		}, nil
	}

	// Evaluate rules in order
	var matchedRules []*RuleMatch
	var actions []*PolicyAction
	finalAction := ActionAllow
	var escalationReason string

	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		// Evaluate all conditions in the rule
		ruleMatches, escalate, escReason, err := e.evaluateRule(ctx, rule, evalCtx)
		if err != nil {
			e.logger.Debug("rule evaluation error",
				Field{Key: "rule_id", Value: rule.RuleId},
				Field{Key: "error", Value: err.Error()})
			continue
		}

		// Handle escalation (semantic condition requires phone-home)
		if escalate {
			finalAction = ActionEscalate
			escalationReason = escReason
			matchedRules = append(matchedRules, &RuleMatch{
				RuleID:   rule.RuleId,
				RuleName: rule.Name,
				Priority: rule.Priority,
			})
			break // Escalation takes priority
		}

		if ruleMatches {
			matchedRules = append(matchedRules, &RuleMatch{
				RuleID:   rule.RuleId,
				RuleName: rule.Name,
				Priority: rule.Priority,
			})

			actions = append(actions, rule.Actions...)

			// Determine action from rule actions
			for _, action := range rule.Actions {
				switch action.ActionType {
				case PolicyActionType_ACTION_TYPE_DENY:
					finalAction = ActionDeny
				case PolicyActionType_ACTION_TYPE_WARN:
					if finalAction == ActionAllow {
						finalAction = ActionWarn
					}
				case PolicyActionType_ACTION_TYPE_REQUIRE_APPROVAL:
					if finalAction != ActionDeny {
						finalAction = ActionRequireApproval
					}
				}

				// Stop if terminal action
				if action.Terminal {
					goto done
				}
			}
		}
	}

done:
	duration := time.Since(startTime)

	reason := "No rules matched"
	if len(matchedRules) > 0 {
		reason = fmt.Sprintf("%d rule(s) matched", len(matchedRules))
	}

	return &Decision{
		Action:               finalAction,
		MatchedPolicy:        policy,
		MatchedRules:         matchedRules,
		Actions:              actions,
		Reason:               reason,
		EvaluationDurationMs: duration.Milliseconds(),
		EscalationReason:     escalationReason,
	}, nil
}

// evaluateRule evaluates all conditions in a rule.
// Returns (matches, needsEscalation, escalationReason, error).
func (e *Evaluator) evaluateRule(ctx context.Context, rule *PolicyRule, evalCtx *EvaluationContext) (matches, needsEscalation bool, escalationReason string, err error) {
	if len(rule.Conditions) == 0 {
		// Rule with no conditions always matches
		return true, false, "", nil
	}

	// All conditions must match (implicit AND)
	for _, condition := range rule.Conditions {
		// Semantic conditions require escalation (phone home to server with LLM)
		if condition.ConditionType == ConditionType_CONDITION_TYPE_SEMANTIC {
			return false, true, fmt.Sprintf("rule %s has semantic condition requiring LLM evaluation", rule.RuleId), nil
		}

		// External calls may be disabled
		if condition.ConditionType == ConditionType_CONDITION_TYPE_EXTERNAL_CALL && !e.externalCallsEnabled {
			return false, true, fmt.Sprintf("rule %s has external call condition (disabled in this context)", rule.RuleId), nil
		}

		matches, err := EvaluateCondition(condition, evalCtx, e.externalCallsEnabled)
		if err != nil {
			return false, false, "", err
		}
		if !matches {
			return false, false, "", nil // Short-circuit on first non-match
		}
	}

	return true, false, "", nil
}

// policyApplies checks if a policy applies to the given evaluation context.
func (e *Evaluator) policyApplies(policy *Policy, ctx *EvaluationContext) bool {
	if policy.Scope == nil {
		return true // No scope means applies to everything
	}

	scope := policy.Scope

	// Check if applies to all
	if scope.ApplyToAll {
		return true
	}

	// Check workflow
	if len(scope.WorkflowIds) > 0 {
		found := false
		for _, wf := range scope.WorkflowIds {
			if wf == ctx.WorkflowId {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check phase
	if len(scope.Phases) > 0 {
		found := false
		for _, phase := range scope.Phases {
			if phase == ctx.Phase {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check roles
	if len(scope.Roles) > 0 {
		userRoleSet := make(map[string]struct{}, len(ctx.UserRoles))
		for _, userRole := range ctx.UserRoles {
			userRoleSet[userRole] = struct{}{}
		}
		found := false
		for _, role := range scope.Roles {
			if _, exists := userRoleSet[role]; exists {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check models
	if len(scope.ModelIds) > 0 {
		found := false
		for _, model := range scope.ModelIds {
			if model == ctx.ModelId {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check tools
	if len(scope.ToolNames) > 0 {
		ctxToolSet := make(map[string]struct{}, len(ctx.ToolNames))
		for _, ctxTool := range ctx.ToolNames {
			ctxToolSet[ctxTool] = struct{}{}
		}
		found := false
		for _, tool := range scope.ToolNames {
			if _, exists := ctxToolSet[tool]; exists {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// ValidatePolicy validates a policy definition for correctness.
func ValidatePolicy(policy *Policy) error {
	if policy == nil {
		return fmt.Errorf("policy is nil")
	}

	if policy.PolicyId == "" {
		return fmt.Errorf("policy_id is required")
	}

	if policy.TenantId == "" {
		return fmt.Errorf("tenant_id is required")
	}

	if len(policy.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}

	for i, rule := range policy.Rules {
		if err := ValidateRule(rule); err != nil {
			return fmt.Errorf("rule %d (%s) invalid: %w", i, rule.RuleId, err)
		}
	}

	return nil
}

// ValidateRule validates a policy rule for correctness.
func ValidateRule(rule *PolicyRule) error {
	if rule == nil {
		return fmt.Errorf("rule is nil")
	}

	if rule.RuleId == "" {
		return fmt.Errorf("rule_id is required")
	}

	if len(rule.Actions) == 0 {
		return fmt.Errorf("rule must have at least one action")
	}

	for i, condition := range rule.Conditions {
		if err := ValidateCondition(condition); err != nil {
			return fmt.Errorf("condition %d invalid: %w", i, err)
		}
	}

	return nil
}

// ValidateCondition validates a condition for correctness.
func ValidateCondition(condition *PolicyCondition) error {
	if condition == nil {
		return fmt.Errorf("condition is nil")
	}

	// Logical conditions must have nested conditions
	if condition.ConditionType == ConditionType_CONDITION_TYPE_LOGICAL {
		if len(condition.NestedConditions) == 0 {
			return fmt.Errorf("logical condition must have nested conditions")
		}
		for i, nested := range condition.NestedConditions {
			if err := ValidateCondition(nested); err != nil {
				return fmt.Errorf("nested condition %d invalid: %w", i, err)
			}
		}
		return nil
	}

	// Non-logical conditions must have a field (except external call)
	if condition.Field == "" && condition.ConditionType != ConditionType_CONDITION_TYPE_EXTERNAL_CALL {
		return fmt.Errorf("condition field is required")
	}

	// IN/NOT_IN conditions must have values list
	if condition.Operator == ConditionOperator_CONDITION_OPERATOR_IN ||
		condition.Operator == ConditionOperator_CONDITION_OPERATOR_NOT_IN {
		if len(condition.Values) == 0 {
			return fmt.Errorf("IN/NOT_IN conditions require values list")
		}
	}

	return nil
}
