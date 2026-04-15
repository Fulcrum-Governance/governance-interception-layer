package policyeval

import (
	"context"
	"sync"
	"testing"
	"time"

)

// mockLogger implements Logger interface for testing.
type mockLogger struct {
	mu       sync.Mutex
	debugs   []string
	warnings []string
}

func (m *mockLogger) Debug(msg string, fields ...Field) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugs = append(m.debugs, msg)
}

func (m *mockLogger) Warn(msg string, fields ...Field) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warnings = append(m.warnings, msg)
}

func (m *mockLogger) getWarnings() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.warnings))
	copy(result, m.warnings)
	return result
}

// Helper functions for creating test policies and rules.

func newTestPolicy(id, tenantID string, priority int32, status PolicyStatus, rules []*PolicyRule) *Policy {
	return &Policy{
		PolicyId: id,
		TenantId: tenantID,
		Name:     "Test Policy " + id,
		Priority: priority,
		Status:   status,
		Rules:    rules,
	}
}

func newTestRule(id string, enabled bool, conditions []*PolicyCondition, actions []*PolicyAction) *PolicyRule {
	return &PolicyRule{
		RuleId:     id,
		Name:       "Test Rule " + id,
		Enabled:    enabled,
		Conditions: conditions,
		Actions:    actions,
	}
}

func newAllowAction(terminal bool) *PolicyAction {
	return &PolicyAction{
		ActionType: PolicyActionType_ACTION_TYPE_ALLOW,
		Terminal:   terminal,
	}
}

func newDenyAction(terminal bool, message string) *PolicyAction {
	return &PolicyAction{
		ActionType: PolicyActionType_ACTION_TYPE_DENY,
		Terminal:   terminal,
		Message:    message,
	}
}

func newWarnAction(terminal bool, message string) *PolicyAction {
	return &PolicyAction{
		ActionType: PolicyActionType_ACTION_TYPE_WARN,
		Terminal:   terminal,
		Message:    message,
	}
}

func newRequireApprovalAction(terminal bool) *PolicyAction {
	return &PolicyAction{
		ActionType: PolicyActionType_ACTION_TYPE_REQUIRE_APPROVAL,
		Terminal:   terminal,
	}
}

func newFieldMatchCondition(field, value string, operator ConditionOperator) *PolicyCondition {
	return &PolicyCondition{
		ConditionType: ConditionType_CONDITION_TYPE_FIELD_MATCH,
		Field:         field,
		Operator:      operator,
		Value:         &PolicyCondition_StringValue{StringValue: value},
	}
}

func newSemanticCondition(intent string) *PolicyCondition {
	return &PolicyCondition{
		ConditionType:  ConditionType_CONDITION_TYPE_SEMANTIC,
		SemanticIntent: intent,
	}
}

// --- Tests ---

func TestNewEvaluator(t *testing.T) {
	tests := []struct {
		name     string
		policies []*Policy
		opts     []Option
		check    func(t *testing.T, e *Evaluator)
	}{
		{
			name:     "creates evaluator with nil policies",
			policies: nil,
			opts:     nil,
			check: func(t *testing.T, e *Evaluator) {
				if e == nil {
					t.Fatal("expected evaluator to be created")
				}
				if e.PolicyCount() != 0 {
					t.Errorf("expected 0 policies, got %d", e.PolicyCount())
				}
			},
		},
		{
			name:     "creates evaluator with empty policies",
			policies: []*Policy{},
			opts:     nil,
			check: func(t *testing.T, e *Evaluator) {
				if e.PolicyCount() != 0 {
					t.Errorf("expected 0 policies, got %d", e.PolicyCount())
				}
			},
		},
		{
			name: "creates evaluator with policies",
			policies: []*Policy{
				newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
				newTestPolicy("p2", "tenant1", 200, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			},
			opts: nil,
			check: func(t *testing.T, e *Evaluator) {
				if e.PolicyCount() != 2 {
					t.Errorf("expected 2 policies, got %d", e.PolicyCount())
				}
			},
		},
		{
			name:     "applies WithMaxEvaluationTime option",
			policies: nil,
			opts:     []Option{WithMaxEvaluationTime(50 * time.Millisecond)},
			check: func(t *testing.T, e *Evaluator) {
				if e.maxEvaluationTime != 50*time.Millisecond {
					t.Errorf("expected maxEvaluationTime 50ms, got %v", e.maxEvaluationTime)
				}
			},
		},
		{
			name:     "applies WithStopOnDeny option - true",
			policies: nil,
			opts:     []Option{WithStopOnDeny(true)},
			check: func(t *testing.T, e *Evaluator) {
				if !e.stopOnDeny {
					t.Error("expected stopOnDeny to be true")
				}
			},
		},
		{
			name:     "applies WithStopOnDeny option - false",
			policies: nil,
			opts:     []Option{WithStopOnDeny(false)},
			check: func(t *testing.T, e *Evaluator) {
				if e.stopOnDeny {
					t.Error("expected stopOnDeny to be false")
				}
			},
		},
		{
			name:     "applies WithExternalCallsEnabled option",
			policies: nil,
			opts:     []Option{WithExternalCallsEnabled(true)},
			check: func(t *testing.T, e *Evaluator) {
				if !e.externalCallsEnabled {
					t.Error("expected externalCallsEnabled to be true")
				}
			},
		},
		{
			name:     "applies WithLogger option",
			policies: nil,
			opts:     []Option{WithLogger(&mockLogger{})},
			check: func(t *testing.T, e *Evaluator) {
				_, ok := e.logger.(*mockLogger)
				if !ok {
					t.Error("expected logger to be mockLogger")
				}
			},
		},
		{
			name:     "applies multiple options",
			policies: nil,
			opts: []Option{
				WithMaxEvaluationTime(100 * time.Millisecond),
				WithStopOnDeny(false),
				WithExternalCallsEnabled(true),
			},
			check: func(t *testing.T, e *Evaluator) {
				if e.maxEvaluationTime != 100*time.Millisecond {
					t.Errorf("expected maxEvaluationTime 100ms, got %v", e.maxEvaluationTime)
				}
				if e.stopOnDeny {
					t.Error("expected stopOnDeny to be false")
				}
				if !e.externalCallsEnabled {
					t.Error("expected externalCallsEnabled to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policies, tt.opts...)
			tt.check(t, e)
		})
	}
}

func TestUpdatePolicies(t *testing.T) {
	tests := []struct {
		name             string
		initialPolicies  []*Policy
		updatePolicies   []*Policy
		expectedCount    int
		expectedPriority []int32 // Expected priority order (highest first)
	}{
		{
			name:            "updates empty evaluator with policies",
			initialPolicies: nil,
			updatePolicies: []*Policy{
				newTestPolicy("p1", "t1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			},
			expectedCount:    1,
			expectedPriority: []int32{100},
		},
		{
			name: "replaces existing policies",
			initialPolicies: []*Policy{
				newTestPolicy("p1", "t1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			},
			updatePolicies: []*Policy{
				newTestPolicy("p2", "t1", 200, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
				newTestPolicy("p3", "t1", 300, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			},
			expectedCount:    2,
			expectedPriority: []int32{300, 200},
		},
		{
			name:            "sorts policies by priority descending",
			initialPolicies: nil,
			updatePolicies: []*Policy{
				newTestPolicy("low", "t1", 10, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
				newTestPolicy("high", "t1", 1000, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
				newTestPolicy("medium", "t1", 500, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			},
			expectedCount:    3,
			expectedPriority: []int32{1000, 500, 10},
		},
		{
			name: "clears policies with nil",
			initialPolicies: []*Policy{
				newTestPolicy("p1", "t1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			},
			updatePolicies:   nil,
			expectedCount:    0,
			expectedPriority: nil,
		},
		{
			name: "clears policies with empty slice",
			initialPolicies: []*Policy{
				newTestPolicy("p1", "t1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			},
			updatePolicies:   []*Policy{},
			expectedCount:    0,
			expectedPriority: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.initialPolicies)
			e.UpdatePolicies(tt.updatePolicies)

			if e.PolicyCount() != tt.expectedCount {
				t.Errorf("expected %d policies, got %d", tt.expectedCount, e.PolicyCount())
			}

			policies := e.Policies()
			if len(policies) != len(tt.expectedPriority) {
				t.Errorf("expected %d policies, got %d", len(tt.expectedPriority), len(policies))
				return
			}

			for i, expectedPri := range tt.expectedPriority {
				if policies[i].Priority != expectedPri {
					t.Errorf("policy at index %d: expected priority %d, got %d", i, expectedPri, policies[i].Priority)
				}
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name           string
		policies       []*Policy
		request        *EvaluationRequest
		opts           []Option
		expectedAction ActionType
		expectedReason string
		expectError    bool
	}{
		{
			name:        "nil request returns error",
			policies:    nil,
			request:     nil,
			expectError: true,
		},
		{
			name:     "empty policy set allows by default",
			policies: nil,
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionAllow,
			expectedReason: "No rules matched - action allowed by default",
		},
		{
			name: "single policy match - allow",
			policies: []*Policy{
				newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newAllowAction(false),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionAllow,
		},
		{
			name: "single policy match - deny",
			policies: []*Policy{
				newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newDenyAction(false, "Access denied"),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionDeny,
		},
		{
			name: "single policy match - warn",
			policies: []*Policy{
				newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newWarnAction(false, "Warning issued"),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionWarn,
		},
		{
			name: "single policy match - require approval",
			policies: []*Policy{
				newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newRequireApprovalAction(false),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionRequireApproval,
		},
		{
			name: "multiple policies - higher priority deny wins",
			policies: []*Policy{
				newTestPolicy("allow-policy", "tenant1", 50, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newAllowAction(false),
					}),
				}),
				newTestPolicy("deny-policy", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newDenyAction(false, "Denied by high priority"),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionDeny,
		},
		{
			name: "decision precedence - deny over escalate",
			policies: []*Policy{
				newTestPolicy("escalate-policy", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, []*PolicyCondition{
						newSemanticCondition("check intent"),
					}, []*PolicyAction{
						newDenyAction(false, "Should escalate"),
					}),
				}),
				newTestPolicy("deny-policy", "tenant1", 50, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newDenyAction(false, "Denied"),
					}),
				}),
			},
			opts: []Option{WithStopOnDeny(false)}, // Continue evaluation
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionDeny,
		},
		{
			name: "decision precedence - escalate over require approval",
			policies: []*Policy{
				newTestPolicy("approval-policy", "tenant1", 50, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newRequireApprovalAction(false),
					}),
				}),
				newTestPolicy("escalate-policy", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, []*PolicyCondition{
						newSemanticCondition("check intent"),
					}, []*PolicyAction{
						newAllowAction(false),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionEscalate,
		},
		{
			name: "decision precedence - require approval over warn",
			policies: []*Policy{
				newTestPolicy("warn-policy", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newWarnAction(false, "Warning"),
					}),
				}),
				newTestPolicy("approval-policy", "tenant1", 50, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newRequireApprovalAction(false),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionRequireApproval,
		},
		{
			name: "decision precedence - warn over allow",
			policies: []*Policy{
				newTestPolicy("allow-policy", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newAllowAction(false),
					}),
				}),
				newTestPolicy("warn-policy", "tenant1", 50, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newWarnAction(false, "Warning"),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionWarn,
		},
		{
			name: "skips inactive policies",
			policies: []*Policy{
				newTestPolicy("inactive", "tenant1", 100, PolicyStatus_POLICY_STATUS_INACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newDenyAction(false, "Should be skipped"),
					}),
				}),
				newTestPolicy("draft", "tenant1", 90, PolicyStatus_POLICY_STATUS_DRAFT, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newDenyAction(false, "Should be skipped"),
					}),
				}),
				newTestPolicy("archived", "tenant1", 80, PolicyStatus_POLICY_STATUS_ARCHIVED, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newDenyAction(false, "Should be skipped"),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionAllow,
			expectedReason: "No rules matched - action allowed by default",
		},
		{
			name: "stopOnDeny stops evaluation",
			policies: []*Policy{
				newTestPolicy("deny-first", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newDenyAction(false, "First deny"),
					}),
				}),
				newTestPolicy("allow-second", "tenant1", 50, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, nil, []*PolicyAction{
						newAllowAction(false),
					}),
				}),
			},
			opts: []Option{WithStopOnDeny(true)},
			request: &EvaluationRequest{
				TenantID: "tenant1",
			},
			expectedAction: ActionDeny,
		},
		{
			name: "semantic condition triggers escalation",
			policies: []*Policy{
				newTestPolicy("semantic-policy", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
					newTestRule("r1", true, []*PolicyCondition{
						newSemanticCondition("detect harmful intent"),
					}, []*PolicyAction{
						newDenyAction(false, "Harmful intent detected"),
					}),
				}),
			},
			request: &EvaluationRequest{
				TenantID:  "tenant1",
				InputText: "some input",
			},
			expectedAction: ActionEscalate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policies, tt.opts...)
			decision, err := e.Evaluate(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.Action != tt.expectedAction {
				t.Errorf("expected action %v, got %v", tt.expectedAction, decision.Action)
			}

			if tt.expectedReason != "" && decision.Reason != tt.expectedReason {
				t.Errorf("expected reason %q, got %q", tt.expectedReason, decision.Reason)
			}
		})
	}
}

func TestEvaluate_ScopeFiltering(t *testing.T) {
	tests := []struct {
		name        string
		scope       *PolicyScope
		request     *EvaluationRequest
		expectMatch bool
	}{
		{
			name:  "nil scope matches all",
			scope: nil,
			request: &EvaluationRequest{
				TenantID:   "tenant1",
				WorkflowID: "wf1",
			},
			expectMatch: true,
		},
		{
			name: "apply_to_all matches all",
			scope: &PolicyScope{
				ApplyToAll: true,
			},
			request: &EvaluationRequest{
				TenantID:   "tenant1",
				WorkflowID: "wf1",
			},
			expectMatch: true,
		},
		{
			name: "workflow filter - match",
			scope: &PolicyScope{
				WorkflowIds: []string{"wf1", "wf2"},
			},
			request: &EvaluationRequest{
				TenantID:   "tenant1",
				WorkflowID: "wf1",
			},
			expectMatch: true,
		},
		{
			name: "workflow filter - no match",
			scope: &PolicyScope{
				WorkflowIds: []string{"wf1", "wf2"},
			},
			request: &EvaluationRequest{
				TenantID:   "tenant1",
				WorkflowID: "wf3",
			},
			expectMatch: false,
		},
		{
			name: "phase filter - match",
			scope: &PolicyScope{
				Phases: []ExecutionPhase{
					ExecutionPhase_EXECUTION_PHASE_PRE_EXECUTION,
					ExecutionPhase_EXECUTION_PHASE_POST_EXECUTION,
				},
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
				Phase:    ExecutionPhase_EXECUTION_PHASE_PRE_EXECUTION,
			},
			expectMatch: true,
		},
		{
			name: "phase filter - no match",
			scope: &PolicyScope{
				Phases: []ExecutionPhase{
					ExecutionPhase_EXECUTION_PHASE_PRE_EXECUTION,
				},
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
				Phase:    ExecutionPhase_EXECUTION_PHASE_POST_LLM_CALL,
			},
			expectMatch: false,
		},
		{
			name: "role filter - match",
			scope: &PolicyScope{
				Roles: []string{"admin", "developer"},
			},
			request: &EvaluationRequest{
				TenantID:  "tenant1",
				UserRoles: []string{"developer", "viewer"},
			},
			expectMatch: true,
		},
		{
			name: "role filter - no match",
			scope: &PolicyScope{
				Roles: []string{"admin"},
			},
			request: &EvaluationRequest{
				TenantID:  "tenant1",
				UserRoles: []string{"developer", "viewer"},
			},
			expectMatch: false,
		},
		{
			name: "model filter - match",
			scope: &PolicyScope{
				ModelIds: []string{"gpt-4", "claude-3"},
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
				ModelID:  "gpt-4",
			},
			expectMatch: true,
		},
		{
			name: "model filter - no match",
			scope: &PolicyScope{
				ModelIds: []string{"gpt-4", "claude-3"},
			},
			request: &EvaluationRequest{
				TenantID: "tenant1",
				ModelID:  "llama-3",
			},
			expectMatch: false,
		},
		{
			name: "tool filter - match",
			scope: &PolicyScope{
				ToolNames: []string{"code_execution", "file_write"},
			},
			request: &EvaluationRequest{
				TenantID:  "tenant1",
				ToolNames: []string{"file_read", "file_write"},
			},
			expectMatch: true,
		},
		{
			name: "tool filter - no match",
			scope: &PolicyScope{
				ToolNames: []string{"code_execution"},
			},
			request: &EvaluationRequest{
				TenantID:  "tenant1",
				ToolNames: []string{"file_read", "file_write"},
			},
			expectMatch: false,
		},
		{
			name: "combined filters - all match",
			scope: &PolicyScope{
				WorkflowIds: []string{"wf1"},
				Phases:      []ExecutionPhase{ExecutionPhase_EXECUTION_PHASE_PRE_TOOL_CALL},
				Roles:       []string{"developer"},
				ModelIds:    []string{"gpt-4"},
				ToolNames:   []string{"code_execution"},
			},
			request: &EvaluationRequest{
				TenantID:   "tenant1",
				WorkflowID: "wf1",
				Phase:      ExecutionPhase_EXECUTION_PHASE_PRE_TOOL_CALL,
				UserRoles:  []string{"developer"},
				ModelID:    "gpt-4",
				ToolNames:  []string{"code_execution"},
			},
			expectMatch: true,
		},
		{
			name: "combined filters - one fails",
			scope: &PolicyScope{
				WorkflowIds: []string{"wf1"},
				Roles:       []string{"admin"}, // This won't match
			},
			request: &EvaluationRequest{
				TenantID:   "tenant1",
				WorkflowID: "wf1",
				UserRoles:  []string{"developer"},
			},
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
				newTestRule("r1", true, nil, []*PolicyAction{
					newDenyAction(false, "Matched"),
				}),
			})
			policy.Scope = tt.scope

			e := NewEvaluator([]*Policy{policy})
			decision, err := e.Evaluate(context.Background(), tt.request)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectMatch {
				if decision.Action != ActionDeny {
					t.Errorf("expected policy to match (deny), got %v", decision.Action)
				}
			} else {
				if decision.Action != ActionAllow {
					t.Errorf("expected policy not to match (allow), got %v", decision.Action)
				}
			}
		})
	}
}

func TestEvaluatePolicy(t *testing.T) {
	tests := []struct {
		name           string
		policy         *Policy
		request        *EvaluationRequest
		expectedAction ActionType
		expectError    bool
	}{
		{
			name:        "nil policy returns error",
			policy:      nil,
			request:     &EvaluationRequest{TenantID: "tenant1"},
			expectError: true,
		},
		{
			name:        "nil request returns error",
			policy:      newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			request:     nil,
			expectError: true,
		},
		{
			name: "inactive policy allows",
			policy: newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_INACTIVE, []*PolicyRule{
				newTestRule("r1", true, nil, []*PolicyAction{
					newDenyAction(false, "Should not apply"),
				}),
			}),
			request:        &EvaluationRequest{TenantID: "tenant1"},
			expectedAction: ActionAllow,
		},
		{
			name: "draft policy allows",
			policy: newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_DRAFT, []*PolicyRule{
				newTestRule("r1", true, nil, []*PolicyAction{
					newDenyAction(false, "Should not apply"),
				}),
			}),
			request:        &EvaluationRequest{TenantID: "tenant1"},
			expectedAction: ActionAllow,
		},
		{
			name: "rule with no conditions always matches",
			policy: newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
				newTestRule("r1", true, nil, []*PolicyAction{
					newDenyAction(false, "Always match"),
				}),
			}),
			request:        &EvaluationRequest{TenantID: "tenant1"},
			expectedAction: ActionDeny,
		},
		{
			name: "disabled rule is skipped",
			policy: newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
				newTestRule("r1", false, nil, []*PolicyAction{
					newDenyAction(false, "Should be skipped"),
				}),
			}),
			request:        &EvaluationRequest{TenantID: "tenant1"},
			expectedAction: ActionAllow,
		},
		{
			name: "terminal action stops rule evaluation",
			policy: newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
				newTestRule("r1", true, nil, []*PolicyAction{
					newWarnAction(true, "Terminal warning"),
				}),
				newTestRule("r2", true, nil, []*PolicyAction{
					newDenyAction(false, "Should not be reached"),
				}),
			}),
			request:        &EvaluationRequest{TenantID: "tenant1"},
			expectedAction: ActionWarn,
		},
		{
			name: "multiple rules evaluated - deny wins",
			policy: newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
				newTestRule("r1", true, nil, []*PolicyAction{
					newWarnAction(false, "Warning first"),
				}),
				newTestRule("r2", true, nil, []*PolicyAction{
					newDenyAction(false, "Deny second"),
				}),
			}),
			request:        &EvaluationRequest{TenantID: "tenant1"},
			expectedAction: ActionDeny,
		},
		{
			name: "condition match required for rule",
			policy: newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
				newTestRule("r1", true, []*PolicyCondition{
					newFieldMatchCondition("user.id", "blocked-user", ConditionOperator_CONDITION_OPERATOR_EQUALS),
				}, []*PolicyAction{
					newDenyAction(false, "Blocked user"),
				}),
			}),
			request: &EvaluationRequest{
				TenantID: "tenant1",
				UserID:   "blocked-user",
			},
			expectedAction: ActionDeny,
		},
		{
			name: "condition no match - rule skipped",
			policy: newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
				newTestRule("r1", true, []*PolicyCondition{
					newFieldMatchCondition("user.id", "blocked-user", ConditionOperator_CONDITION_OPERATOR_EQUALS),
				}, []*PolicyAction{
					newDenyAction(false, "Blocked user"),
				}),
			}),
			request: &EvaluationRequest{
				TenantID: "tenant1",
				UserID:   "allowed-user",
			},
			expectedAction: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(nil)
			decision, err := e.EvaluatePolicy(context.Background(), tt.policy, tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.Action != tt.expectedAction {
				t.Errorf("expected action %v, got %v", tt.expectedAction, decision.Action)
			}
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name        string
		policy      *Policy
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil policy",
			policy:      nil,
			expectError: true,
			errorMsg:    "policy is nil",
		},
		{
			name: "missing policy_id",
			policy: &Policy{
				TenantId: "tenant1",
				Rules: []*PolicyRule{
					{RuleId: "r1", Actions: []*PolicyAction{{ActionType: PolicyActionType_ACTION_TYPE_ALLOW}}},
				},
			},
			expectError: true,
			errorMsg:    "policy_id is required",
		},
		{
			name: "missing tenant_id",
			policy: &Policy{
				PolicyId: "p1",
				Rules: []*PolicyRule{
					{RuleId: "r1", Actions: []*PolicyAction{{ActionType: PolicyActionType_ACTION_TYPE_ALLOW}}},
				},
			},
			expectError: true,
			errorMsg:    "tenant_id is required",
		},
		{
			name: "no rules",
			policy: &Policy{
				PolicyId: "p1",
				TenantId: "tenant1",
				Rules:    nil,
			},
			expectError: true,
			errorMsg:    "policy must have at least one rule",
		},
		{
			name: "empty rules slice",
			policy: &Policy{
				PolicyId: "p1",
				TenantId: "tenant1",
				Rules:    []*PolicyRule{},
			},
			expectError: true,
			errorMsg:    "policy must have at least one rule",
		},
		{
			name: "invalid rule",
			policy: &Policy{
				PolicyId: "p1",
				TenantId: "tenant1",
				Rules: []*PolicyRule{
					{RuleId: "", Actions: []*PolicyAction{{ActionType: PolicyActionType_ACTION_TYPE_ALLOW}}},
				},
			},
			expectError: true,
			errorMsg:    "rule_id is required",
		},
		{
			name: "valid policy",
			policy: &Policy{
				PolicyId: "p1",
				TenantId: "tenant1",
				Rules: []*PolicyRule{
					{RuleId: "r1", Actions: []*PolicyAction{{ActionType: PolicyActionType_ACTION_TYPE_ALLOW}}},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicy(tt.policy)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					// Check if error contains expected message (for wrapped errors)
					if !contains(err.Error(), tt.errorMsg) {
						t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        *PolicyRule
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil rule",
			rule:        nil,
			expectError: true,
			errorMsg:    "rule is nil",
		},
		{
			name: "missing rule_id",
			rule: &PolicyRule{
				Actions: []*PolicyAction{{ActionType: PolicyActionType_ACTION_TYPE_ALLOW}},
			},
			expectError: true,
			errorMsg:    "rule_id is required",
		},
		{
			name: "no actions",
			rule: &PolicyRule{
				RuleId: "r1",
			},
			expectError: true,
			errorMsg:    "rule must have at least one action",
		},
		{
			name: "empty actions",
			rule: &PolicyRule{
				RuleId:  "r1",
				Actions: []*PolicyAction{},
			},
			expectError: true,
			errorMsg:    "rule must have at least one action",
		},
		{
			name: "invalid condition",
			rule: &PolicyRule{
				RuleId: "r1",
				Conditions: []*PolicyCondition{
					nil,
				},
				Actions: []*PolicyAction{{ActionType: PolicyActionType_ACTION_TYPE_ALLOW}},
			},
			expectError: true,
			errorMsg:    "condition is nil",
		},
		{
			name: "valid rule with conditions",
			rule: &PolicyRule{
				RuleId: "r1",
				Conditions: []*PolicyCondition{
					{
						ConditionType: ConditionType_CONDITION_TYPE_FIELD_MATCH,
						Field:         "user.id",
						Operator:      ConditionOperator_CONDITION_OPERATOR_EQUALS,
						Value:         &PolicyCondition_StringValue{StringValue: "test"},
					},
				},
				Actions: []*PolicyAction{{ActionType: PolicyActionType_ACTION_TYPE_ALLOW}},
			},
			expectError: false,
		},
		{
			name: "valid rule without conditions",
			rule: &PolicyRule{
				RuleId:  "r1",
				Actions: []*PolicyAction{{ActionType: PolicyActionType_ACTION_TYPE_ALLOW}},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRule(tt.rule)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateCondition(t *testing.T) {
	tests := []struct {
		name        string
		condition   *PolicyCondition
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil condition",
			condition:   nil,
			expectError: true,
			errorMsg:    "condition is nil",
		},
		{
			name: "missing field for non-logical condition",
			condition: &PolicyCondition{
				ConditionType: ConditionType_CONDITION_TYPE_FIELD_MATCH,
				Field:         "",
			},
			expectError: true,
			errorMsg:    "condition field is required",
		},
		{
			name: "IN operator without values",
			condition: &PolicyCondition{
				ConditionType: ConditionType_CONDITION_TYPE_IN_LIST,
				Field:         "user.role",
				Operator:      ConditionOperator_CONDITION_OPERATOR_IN,
				Values:        nil,
			},
			expectError: true,
			errorMsg:    "IN/NOT_IN conditions require values list",
		},
		{
			name: "NOT_IN operator without values",
			condition: &PolicyCondition{
				ConditionType: ConditionType_CONDITION_TYPE_IN_LIST,
				Field:         "user.role",
				Operator:      ConditionOperator_CONDITION_OPERATOR_NOT_IN,
				Values:        nil,
			},
			expectError: true,
			errorMsg:    "IN/NOT_IN conditions require values list",
		},
		{
			name: "logical condition without nested conditions",
			condition: &PolicyCondition{
				ConditionType:    ConditionType_CONDITION_TYPE_LOGICAL,
				LogicalOperator:  LogicalOperator_LOGICAL_OPERATOR_AND,
				NestedConditions: nil,
			},
			expectError: true,
			errorMsg:    "logical condition must have nested conditions",
		},
		{
			name: "logical condition with invalid nested condition",
			condition: &PolicyCondition{
				ConditionType:   ConditionType_CONDITION_TYPE_LOGICAL,
				LogicalOperator: LogicalOperator_LOGICAL_OPERATOR_AND,
				NestedConditions: []*PolicyCondition{
					nil,
				},
			},
			expectError: true,
			errorMsg:    "condition is nil",
		},
		{
			name: "valid field match condition",
			condition: &PolicyCondition{
				ConditionType: ConditionType_CONDITION_TYPE_FIELD_MATCH,
				Field:         "user.id",
				Operator:      ConditionOperator_CONDITION_OPERATOR_EQUALS,
				Value:         &PolicyCondition_StringValue{StringValue: "test"},
			},
			expectError: false,
		},
		{
			name: "valid IN condition",
			condition: &PolicyCondition{
				ConditionType: ConditionType_CONDITION_TYPE_IN_LIST,
				Field:         "user.role",
				Operator:      ConditionOperator_CONDITION_OPERATOR_IN,
				Values:        []string{"admin", "developer"},
			},
			expectError: false,
		},
		{
			name: "valid logical condition",
			condition: &PolicyCondition{
				ConditionType:   ConditionType_CONDITION_TYPE_LOGICAL,
				LogicalOperator: LogicalOperator_LOGICAL_OPERATOR_AND,
				NestedConditions: []*PolicyCondition{
					{
						ConditionType: ConditionType_CONDITION_TYPE_FIELD_MATCH,
						Field:         "user.id",
						Operator:      ConditionOperator_CONDITION_OPERATOR_EQUALS,
						Value:         &PolicyCondition_StringValue{StringValue: "test"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "external call condition without field is valid",
			condition: &PolicyCondition{
				ConditionType: ConditionType_CONDITION_TYPE_EXTERNAL_CALL,
				Field:         "",
				Value:         &PolicyCondition_StringValue{StringValue: "https://example.com/check"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCondition(tt.condition)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPolicies(t *testing.T) {
	policies := []*Policy{
		newTestPolicy("p1", "t1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
		newTestPolicy("p2", "t1", 200, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
	}

	e := NewEvaluator(policies)

	// Get policies and verify they are a copy
	result := e.Policies()
	if len(result) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(result))
	}

	// Modify the returned slice
	result[0] = nil

	// Original should be unchanged
	original := e.Policies()
	if original[0] == nil {
		t.Error("modifying returned slice should not affect internal state")
	}
}

func TestPolicyCount(t *testing.T) {
	tests := []struct {
		name     string
		policies []*Policy
		expected int
	}{
		{
			name:     "nil policies",
			policies: nil,
			expected: 0,
		},
		{
			name:     "empty policies",
			policies: []*Policy{},
			expected: 0,
		},
		{
			name: "multiple policies",
			policies: []*Policy{
				newTestPolicy("p1", "t1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
				newTestPolicy("p2", "t1", 200, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
				newTestPolicy("p3", "t1", 300, PolicyStatus_POLICY_STATUS_ACTIVE, nil),
			},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policies)
			if e.PolicyCount() != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, e.PolicyCount())
			}
		})
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Create evaluator with initial policy
	initialPolicy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, nil, []*PolicyAction{
			newAllowAction(false),
		}),
	})
	e := NewEvaluator([]*Policy{initialPolicy})

	// Run concurrent operations
	var wg sync.WaitGroup
	numGoroutines := 100
	iterations := 100

	// Concurrent Evaluate calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				req := &EvaluationRequest{
					TenantID: "tenant1",
					UserID:   "user1",
				}
				_, err := e.Evaluate(context.Background(), req)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		}()
	}

	// Concurrent UpdatePolicies calls
	for i := 0; i < numGoroutines/10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations/10; j++ {
				policies := []*Policy{
					newTestPolicy("p1", "tenant1", int32(idx*100+j), PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
						newTestRule("r1", true, nil, []*PolicyAction{
							newAllowAction(false),
						}),
					}),
				}
				e.UpdatePolicies(policies)
			}
		}(i)
	}

	// Concurrent PolicyCount calls
	for i := 0; i < numGoroutines/5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = e.PolicyCount()
			}
		}()
	}

	// Concurrent Policies calls
	for i := 0; i < numGoroutines/5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = e.Policies()
			}
		}()
	}

	wg.Wait()
}

func TestEvaluationTimeout(t *testing.T) {
	// Create a logger to capture warnings
	logger := &mockLogger{}

	// Create evaluator with very short timeout
	e := NewEvaluator(nil, WithMaxEvaluationTime(1*time.Nanosecond), WithLogger(logger))

	// Create policy with multiple rules to ensure evaluation takes time
	var rules []*PolicyRule
	for i := 0; i < 100; i++ {
		rules = append(rules, newTestRule("r"+string(rune(i)), true, nil, []*PolicyAction{
			newAllowAction(false),
		}))
	}
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, rules)
	e.UpdatePolicies([]*Policy{policy})

	// Evaluate and expect timeout warning
	req := &EvaluationRequest{TenantID: "tenant1"}
	_, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that warning was logged
	warnings := logger.getWarnings()
	if len(warnings) == 0 {
		t.Error("expected timeout warning to be logged")
	}
}

func TestExternalCallConditionDisabled(t *testing.T) {
	// Create policy with external call condition
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, []*PolicyCondition{
			{
				ConditionType: ConditionType_CONDITION_TYPE_EXTERNAL_CALL,
				Value:         &PolicyCondition_StringValue{StringValue: "https://example.com/check"},
			},
		}, []*PolicyAction{
			newDenyAction(false, "External check failed"),
		}),
	})

	// Test with external calls disabled (default)
	e := NewEvaluator([]*Policy{policy})
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should escalate because external calls are disabled
	if decision.Action != ActionEscalate {
		t.Errorf("expected escalate action (external calls disabled), got %v", decision.Action)
	}
}

// Note: ActionType.String() and EvaluationRequest/FromProtoContext are tested in decision_test.go

func TestDecisionFields(t *testing.T) {
	// Test that Decision struct fields are populated correctly
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, nil, []*PolicyAction{
			newDenyAction(false, "Denied"),
		}),
	})

	e := NewEvaluator([]*Policy{policy})
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.MatchedPolicy == nil {
		t.Error("expected MatchedPolicy to be set")
	}
	if decision.MatchedPolicy.PolicyId != "p1" {
		t.Errorf("expected PolicyId p1, got %s", decision.MatchedPolicy.PolicyId)
	}
	if len(decision.MatchedRules) != 1 {
		t.Errorf("expected 1 matched rule, got %d", len(decision.MatchedRules))
	}
	if decision.MatchedRules[0].RuleID != "r1" {
		t.Errorf("expected RuleID r1, got %s", decision.MatchedRules[0].RuleID)
	}
	if len(decision.Actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(decision.Actions))
	}
	if decision.EvaluationDurationMs < 0 {
		t.Errorf("expected non-negative duration, got %d", decision.EvaluationDurationMs)
	}
	if decision.Reason == "" {
		t.Error("expected Reason to be set")
	}
}

func TestMultipleConditionsImplicitAnd(t *testing.T) {
	// Test that multiple conditions are ANDed together
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, []*PolicyCondition{
			newFieldMatchCondition("user.id", "user1", ConditionOperator_CONDITION_OPERATOR_EQUALS),
			newFieldMatchCondition("model.id", "gpt-4", ConditionOperator_CONDITION_OPERATOR_EQUALS),
		}, []*PolicyAction{
			newDenyAction(false, "Both conditions matched"),
		}),
	})

	e := NewEvaluator([]*Policy{policy})

	tests := []struct {
		name           string
		request        *EvaluationRequest
		expectedAction ActionType
	}{
		{
			name: "both conditions match",
			request: &EvaluationRequest{
				TenantID: "tenant1",
				UserID:   "user1",
				ModelID:  "gpt-4",
			},
			expectedAction: ActionDeny,
		},
		{
			name: "first condition matches, second does not",
			request: &EvaluationRequest{
				TenantID: "tenant1",
				UserID:   "user1",
				ModelID:  "claude-3",
			},
			expectedAction: ActionAllow,
		},
		{
			name: "second condition matches, first does not",
			request: &EvaluationRequest{
				TenantID: "tenant1",
				UserID:   "user2",
				ModelID:  "gpt-4",
			},
			expectedAction: ActionAllow,
		},
		{
			name: "neither condition matches",
			request: &EvaluationRequest{
				TenantID: "tenant1",
				UserID:   "user2",
				ModelID:  "claude-3",
			},
			expectedAction: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := e.Evaluate(context.Background(), tt.request)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Action != tt.expectedAction {
				t.Errorf("expected %v, got %v", tt.expectedAction, decision.Action)
			}
		})
	}
}

func TestEscalationReason(t *testing.T) {
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, []*PolicyCondition{
			newSemanticCondition("detect harmful content"),
		}, []*PolicyAction{
			newDenyAction(false, "Harmful content"),
		}),
	})

	e := NewEvaluator([]*Policy{policy})
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Action != ActionEscalate {
		t.Errorf("expected escalate, got %v", decision.Action)
	}
	if decision.EscalationReason == "" {
		t.Error("expected EscalationReason to be set")
	}
	if !contains(decision.EscalationReason, "semantic condition") {
		t.Errorf("expected escalation reason to mention semantic condition, got %q", decision.EscalationReason)
	}
}

func TestNoopLogger(t *testing.T) {
	// Ensure noopLogger doesn't panic
	logger := noopLogger{}
	logger.Debug("test message", Field{Key: "key", Value: "value"})
	logger.Warn("test warning", Field{Key: "key", Value: "value"})
	// Test passes if no panic
}

func TestEvaluatePolicyWithConditionError(t *testing.T) {
	// Test condition evaluation error logging
	logger := &mockLogger{}

	// Create a policy with a condition that will produce an error
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, []*PolicyCondition{
			{
				ConditionType: ConditionType_CONDITION_TYPE_FIELD_MATCH,
				Field:         "invalid", // Invalid field format
				Operator:      ConditionOperator_CONDITION_OPERATOR_EQUALS,
				Value:         &PolicyCondition_StringValue{StringValue: "test"},
			},
		}, []*PolicyAction{
			newDenyAction(false, "Should not match"),
		}),
	})

	e := NewEvaluator([]*Policy{policy}, WithLogger(logger))
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should allow because rule condition errored
	if decision.Action != ActionAllow {
		t.Errorf("expected allow (condition error), got %v", decision.Action)
	}
}

func TestEvaluatePolicyErrorLogging(t *testing.T) {
	// Test that policy evaluation errors are logged and policy is skipped
	logger := &mockLogger{}

	// Create policy with invalid condition that causes error in evaluatePolicy
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, []*PolicyCondition{
			{
				ConditionType: ConditionType_CONDITION_TYPE_REGEX,
				Field:         "input.text",
				Operator:      ConditionOperator_CONDITION_OPERATOR_MATCHES,
				Value:         &PolicyCondition_StringValue{StringValue: "[invalid"}, // Invalid regex
			},
		}, []*PolicyAction{
			newDenyAction(false, "Should not match"),
		}),
	})

	e := NewEvaluator([]*Policy{policy}, WithLogger(logger))
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{
		TenantID:  "tenant1",
		InputText: "test input",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should allow because rule condition errored
	if decision.Action != ActionAllow {
		t.Errorf("expected allow (condition error), got %v", decision.Action)
	}
}

func TestRuleMatchNameAndPriority(t *testing.T) {
	// Test that RuleMatch captures name and priority correctly
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		{
			RuleId:   "r1",
			Name:     "Important Rule",
			Enabled:  true,
			Priority: 50,
			Actions:  []*PolicyAction{newWarnAction(false, "Warning")},
		},
	})

	e := NewEvaluator([]*Policy{policy})
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(decision.MatchedRules) != 1 {
		t.Fatalf("expected 1 matched rule, got %d", len(decision.MatchedRules))
	}

	rule := decision.MatchedRules[0]
	if rule.RuleID != "r1" {
		t.Errorf("expected RuleID r1, got %s", rule.RuleID)
	}
	if rule.RuleName != "Important Rule" {
		t.Errorf("expected RuleName 'Important Rule', got %s", rule.RuleName)
	}
	if rule.Priority != 50 {
		t.Errorf("expected Priority 50, got %d", rule.Priority)
	}
}

func TestStopOnDenyFalseContinuesEvaluation(t *testing.T) {
	// Test that stopOnDeny=false continues evaluation after first deny
	policies := []*Policy{
		newTestPolicy("deny-first", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
			newTestRule("r1", true, nil, []*PolicyAction{
				newDenyAction(false, "First deny"),
			}),
		}),
		newTestPolicy("warn-second", "tenant1", 50, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
			newTestRule("r2", true, nil, []*PolicyAction{
				newWarnAction(false, "Second warn"),
			}),
		}),
	}

	e := NewEvaluator(policies, WithStopOnDeny(false))
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Final decision should be deny (highest precedence)
	if decision.Action != ActionDeny {
		t.Errorf("expected deny, got %v", decision.Action)
	}

	// Should have collected rules from both policies (continue after first deny)
	if len(decision.MatchedRules) != 2 {
		t.Errorf("expected 2 matched rules, got %d", len(decision.MatchedRules))
	}
}

func TestMatchedPolicySetOnFirstMatch(t *testing.T) {
	// Test that MatchedPolicy is set on first meaningful match for escalate/warn/require_approval
	policies := []*Policy{
		newTestPolicy("warn-first", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
			newTestRule("r1", true, nil, []*PolicyAction{
				newWarnAction(false, "First warning"),
			}),
		}),
		newTestPolicy("warn-second", "tenant1", 50, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
			newTestRule("r2", true, nil, []*PolicyAction{
				newWarnAction(false, "Second warning"),
			}),
		}),
	}

	e := NewEvaluator(policies)
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should match first policy (highest priority)
	if decision.MatchedPolicy == nil {
		t.Fatal("expected MatchedPolicy to be set")
	}
	if decision.MatchedPolicy.PolicyId != "warn-first" {
		t.Errorf("expected MatchedPolicy to be 'warn-first', got %s", decision.MatchedPolicy.PolicyId)
	}
}

func TestTerminalActionInMiddleOfRules(t *testing.T) {
	// Test that terminal action in the middle of rules stops further rule evaluation
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, nil, []*PolicyAction{
			newAllowAction(false), // Non-terminal allow
		}),
		newTestRule("r2", true, nil, []*PolicyAction{
			newWarnAction(true, "Terminal warning"), // Terminal
		}),
		newTestRule("r3", true, nil, []*PolicyAction{
			newDenyAction(false, "Should not be reached"),
		}),
	})

	e := NewEvaluator([]*Policy{policy})
	decision, err := e.EvaluatePolicy(context.Background(), policy, &EvaluationRequest{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be warn (terminal stopped at r2)
	if decision.Action != ActionWarn {
		t.Errorf("expected warn, got %v", decision.Action)
	}

	// Should have matched r1 and r2 but not r3
	if len(decision.MatchedRules) != 2 {
		t.Errorf("expected 2 matched rules, got %d", len(decision.MatchedRules))
	}
}

func TestEmptyUserRolesInScopeFiltering(t *testing.T) {
	// Test scope filtering with empty user roles
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, nil, []*PolicyAction{
			newDenyAction(false, "Matched"),
		}),
	})
	policy.Scope = &PolicyScope{
		Roles: []string{"admin"},
	}

	e := NewEvaluator([]*Policy{policy})

	// Request with empty roles should not match
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{
		TenantID:  "tenant1",
		UserRoles: []string{}, // Empty roles
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Action != ActionAllow {
		t.Errorf("expected allow (scope not matched), got %v", decision.Action)
	}
}

func TestEmptyToolNamesInScopeFiltering(t *testing.T) {
	// Test scope filtering with empty tool names
	policy := newTestPolicy("p1", "tenant1", 100, PolicyStatus_POLICY_STATUS_ACTIVE, []*PolicyRule{
		newTestRule("r1", true, nil, []*PolicyAction{
			newDenyAction(false, "Matched"),
		}),
	})
	policy.Scope = &PolicyScope{
		ToolNames: []string{"dangerous_tool"},
	}

	e := NewEvaluator([]*Policy{policy})

	// Request with empty tools should not match
	decision, err := e.Evaluate(context.Background(), &EvaluationRequest{
		TenantID:  "tenant1",
		ToolNames: []string{}, // Empty tools
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Action != ActionAllow {
		t.Errorf("expected allow (scope not matched), got %v", decision.Action)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
