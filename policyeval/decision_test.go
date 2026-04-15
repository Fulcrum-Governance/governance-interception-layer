package policyeval

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionType_String(t *testing.T) {
	tests := []struct {
		name     string
		action   ActionType
		expected string
	}{
		{
			name:     "ActionAllow returns allow",
			action:   ActionAllow,
			expected: "allow",
		},
		{
			name:     "ActionDeny returns deny",
			action:   ActionDeny,
			expected: "deny",
		},
		{
			name:     "ActionEscalate returns escalate",
			action:   ActionEscalate,
			expected: "escalate",
		},
		{
			name:     "ActionWarn returns warn",
			action:   ActionWarn,
			expected: "warn",
		},
		{
			name:     "ActionRequireApproval returns require_approval",
			action:   ActionRequireApproval,
			expected: "require_approval",
		},
		{
			name:     "Unknown value returns unknown",
			action:   ActionType(99),
			expected: "unknown",
		},
		{
			name:     "Negative value returns unknown",
			action:   ActionType(-1),
			expected: "unknown",
		},
		{
			name:     "Large value returns unknown",
			action:   ActionType(1000),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.action.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluationRequest_ToProtoContext(t *testing.T) {
	tests := []struct {
		name     string
		request  *EvaluationRequest
		validate func(t *testing.T, ctx *EvaluationContext)
	}{
		{
			name: "all fields populated",
			request: &EvaluationRequest{
				TenantID:   "tenant-123",
				UserID:     "user-456",
				UserRoles:  []string{"admin", "developer"},
				WorkflowID: "workflow-789",
				EnvelopeID: "envelope-abc",
				Phase:      ExecutionPhase_EXECUTION_PHASE_PRE_EXECUTION,
				ModelID:    "gpt-4",
				ToolNames:  []string{"read_file", "write_file"},
				InputText:  "Hello, world!",
				OutputText: "Response text",
				Attributes: map[string]string{
					"env":     "production",
					"region":  "us-west-2",
					"version": "1.0.0",
				},
			},
			validate: func(t *testing.T, ctx *EvaluationContext) {
				assert.Equal(t, "tenant-123", ctx.TenantId)
				assert.Equal(t, "user-456", ctx.UserId)
				assert.Equal(t, []string{"admin", "developer"}, ctx.UserRoles)
				assert.Equal(t, "workflow-789", ctx.WorkflowId)
				assert.Equal(t, "envelope-abc", ctx.EnvelopeId)
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_PRE_EXECUTION, ctx.Phase)
				assert.Equal(t, "gpt-4", ctx.ModelId)
				assert.Equal(t, []string{"read_file", "write_file"}, ctx.ToolNames)
				assert.Equal(t, "Hello, world!", ctx.InputText)
				assert.Equal(t, "Response text", ctx.OutputText)
				require.Len(t, ctx.Attributes, 3)
				assert.Equal(t, "production", ctx.Attributes["env"])
				assert.Equal(t, "us-west-2", ctx.Attributes["region"])
				assert.Equal(t, "1.0.0", ctx.Attributes["version"])
			},
		},
		{
			name:    "empty request",
			request: &EvaluationRequest{},
			validate: func(t *testing.T, ctx *EvaluationContext) {
				assert.Empty(t, ctx.TenantId)
				assert.Empty(t, ctx.UserId)
				assert.Nil(t, ctx.UserRoles)
				assert.Empty(t, ctx.WorkflowId)
				assert.Empty(t, ctx.EnvelopeId)
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_UNSPECIFIED, ctx.Phase)
				assert.Empty(t, ctx.ModelId)
				assert.Nil(t, ctx.ToolNames)
				assert.Empty(t, ctx.InputText)
				assert.Empty(t, ctx.OutputText)
				assert.Nil(t, ctx.Attributes)
			},
		},
		{
			name: "nil slices and map",
			request: &EvaluationRequest{
				TenantID:   "tenant-only",
				UserRoles:  nil,
				ToolNames:  nil,
				Attributes: nil,
			},
			validate: func(t *testing.T, ctx *EvaluationContext) {
				assert.Equal(t, "tenant-only", ctx.TenantId)
				assert.Nil(t, ctx.UserRoles)
				assert.Nil(t, ctx.ToolNames)
				assert.Nil(t, ctx.Attributes)
			},
		},
		{
			name: "empty slices and map",
			request: &EvaluationRequest{
				UserID:     "user-empty-collections",
				UserRoles:  []string{},
				ToolNames:  []string{},
				Attributes: map[string]string{},
			},
			validate: func(t *testing.T, ctx *EvaluationContext) {
				assert.Equal(t, "user-empty-collections", ctx.UserId)
				assert.Empty(t, ctx.UserRoles)
				assert.Empty(t, ctx.ToolNames)
				assert.Empty(t, ctx.Attributes)
			},
		},
		{
			name: "all execution phases",
			request: &EvaluationRequest{
				Phase: ExecutionPhase_EXECUTION_PHASE_POST_EXECUTION,
			},
			validate: func(t *testing.T, ctx *EvaluationContext) {
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_POST_EXECUTION, ctx.Phase)
			},
		},
		{
			name: "single element slices",
			request: &EvaluationRequest{
				UserRoles: []string{"single_role"},
				ToolNames: []string{"single_tool"},
			},
			validate: func(t *testing.T, ctx *EvaluationContext) {
				assert.Equal(t, []string{"single_role"}, ctx.UserRoles)
				assert.Equal(t, []string{"single_tool"}, ctx.ToolNames)
			},
		},
		{
			name: "special characters in strings",
			request: &EvaluationRequest{
				TenantID:   "tenant-with-special!@#$%",
				InputText:  "Input with\nnewlines\tand\ttabs",
				OutputText: "Unicode: \u4e2d\u6587 \U0001F600",
				Attributes: map[string]string{
					"key-with-dashes":      "value",
					"key_with_underscores": "value2",
					"key.with.dots":        "value3",
				},
			},
			validate: func(t *testing.T, ctx *EvaluationContext) {
				assert.Equal(t, "tenant-with-special!@#$%", ctx.TenantId)
				assert.Equal(t, "Input with\nnewlines\tand\ttabs", ctx.InputText)
				assert.Equal(t, "Unicode: \u4e2d\u6587 \U0001F600", ctx.OutputText)
				assert.Equal(t, "value", ctx.Attributes["key-with-dashes"])
				assert.Equal(t, "value2", ctx.Attributes["key_with_underscores"])
				assert.Equal(t, "value3", ctx.Attributes["key.with.dots"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.request.ToProtoContext()
			require.NotNil(t, ctx)
			tt.validate(t, ctx)
		})
	}
}

func TestFromProtoContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      *EvaluationContext
		validate func(t *testing.T, req *EvaluationRequest)
	}{
		{
			name: "all fields populated",
			ctx: &EvaluationContext{
				TenantId:   "tenant-123",
				UserId:     "user-456",
				UserRoles:  []string{"admin", "developer"},
				WorkflowId: "workflow-789",
				EnvelopeId: "envelope-abc",
				Phase:      ExecutionPhase_EXECUTION_PHASE_PRE_LLM_CALL,
				ModelId:    "claude-3-opus",
				ToolNames:  []string{"search", "calculator"},
				InputText:  "What is 2+2?",
				OutputText: "The answer is 4",
				Attributes: map[string]string{
					"priority": "high",
					"source":   "api",
				},
			},
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Equal(t, "tenant-123", req.TenantID)
				assert.Equal(t, "user-456", req.UserID)
				assert.Equal(t, []string{"admin", "developer"}, req.UserRoles)
				assert.Equal(t, "workflow-789", req.WorkflowID)
				assert.Equal(t, "envelope-abc", req.EnvelopeID)
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_PRE_LLM_CALL, req.Phase)
				assert.Equal(t, "claude-3-opus", req.ModelID)
				assert.Equal(t, []string{"search", "calculator"}, req.ToolNames)
				assert.Equal(t, "What is 2+2?", req.InputText)
				assert.Equal(t, "The answer is 4", req.OutputText)
				require.Len(t, req.Attributes, 2)
				assert.Equal(t, "high", req.Attributes["priority"])
				assert.Equal(t, "api", req.Attributes["source"])
			},
		},
		{
			name: "nil input returns empty struct",
			ctx:  nil,
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Empty(t, req.TenantID)
				assert.Empty(t, req.UserID)
				assert.Nil(t, req.UserRoles)
				assert.Empty(t, req.WorkflowID)
				assert.Empty(t, req.EnvelopeID)
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_UNSPECIFIED, req.Phase)
				assert.Empty(t, req.ModelID)
				assert.Nil(t, req.ToolNames)
				assert.Empty(t, req.InputText)
				assert.Empty(t, req.OutputText)
				assert.Nil(t, req.Attributes)
			},
		},
		{
			name: "empty context fields",
			ctx:  &EvaluationContext{},
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Empty(t, req.TenantID)
				assert.Empty(t, req.UserID)
				assert.Nil(t, req.UserRoles)
				assert.Empty(t, req.WorkflowID)
				assert.Empty(t, req.EnvelopeID)
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_UNSPECIFIED, req.Phase)
				assert.Empty(t, req.ModelID)
				assert.Nil(t, req.ToolNames)
				assert.Empty(t, req.InputText)
				assert.Empty(t, req.OutputText)
				assert.Nil(t, req.Attributes)
			},
		},
		{
			name: "partial fields populated",
			ctx: &EvaluationContext{
				TenantId: "tenant-partial",
				ModelId:  "gpt-4-turbo",
			},
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Equal(t, "tenant-partial", req.TenantID)
				assert.Empty(t, req.UserID)
				assert.Nil(t, req.UserRoles)
				assert.Empty(t, req.WorkflowID)
				assert.Empty(t, req.EnvelopeID)
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_UNSPECIFIED, req.Phase)
				assert.Equal(t, "gpt-4-turbo", req.ModelID)
				assert.Nil(t, req.ToolNames)
			},
		},
		{
			name: "all execution phases - pre_tool_call",
			ctx: &EvaluationContext{
				Phase: ExecutionPhase_EXECUTION_PHASE_PRE_TOOL_CALL,
			},
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_PRE_TOOL_CALL, req.Phase)
			},
		},
		{
			name: "all execution phases - post_tool_call",
			ctx: &EvaluationContext{
				Phase: ExecutionPhase_EXECUTION_PHASE_POST_TOOL_CALL,
			},
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_POST_TOOL_CALL, req.Phase)
			},
		},
		{
			name: "all execution phases - post_llm_call",
			ctx: &EvaluationContext{
				Phase: ExecutionPhase_EXECUTION_PHASE_POST_LLM_CALL,
			},
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Equal(t, ExecutionPhase_EXECUTION_PHASE_POST_LLM_CALL, req.Phase)
			},
		},
		{
			name: "empty slices",
			ctx: &EvaluationContext{
				UserRoles: []string{},
				ToolNames: []string{},
			},
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Empty(t, req.UserRoles)
				assert.Empty(t, req.ToolNames)
			},
		},
		{
			name: "empty attributes map",
			ctx: &EvaluationContext{
				Attributes: map[string]string{},
			},
			validate: func(t *testing.T, req *EvaluationRequest) {
				assert.Empty(t, req.Attributes)
			},
		},
		{
			name: "large attributes map",
			ctx: &EvaluationContext{
				Attributes: map[string]string{
					"key1":  "value1",
					"key2":  "value2",
					"key3":  "value3",
					"key4":  "value4",
					"key5":  "value5",
					"key6":  "value6",
					"key7":  "value7",
					"key8":  "value8",
					"key9":  "value9",
					"key10": "value10",
				},
			},
			validate: func(t *testing.T, req *EvaluationRequest) {
				require.Len(t, req.Attributes, 10)
				assert.Equal(t, "value1", req.Attributes["key1"])
				assert.Equal(t, "value10", req.Attributes["key10"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := FromProtoContext(tt.ctx)
			require.NotNil(t, req)
			tt.validate(t, req)
		})
	}
}

func TestRoundTrip_ToProtoContext_FromProtoContext(t *testing.T) {
	tests := []struct {
		name    string
		request *EvaluationRequest
	}{
		{
			name: "full round trip",
			request: &EvaluationRequest{
				TenantID:   "tenant-roundtrip",
				UserID:     "user-roundtrip",
				UserRoles:  []string{"admin", "user", "viewer"},
				WorkflowID: "workflow-roundtrip",
				EnvelopeID: "envelope-roundtrip",
				Phase:      ExecutionPhase_EXECUTION_PHASE_PRE_EXECUTION,
				ModelID:    "gpt-4",
				ToolNames:  []string{"tool1", "tool2", "tool3"},
				InputText:  "Input text for round trip",
				OutputText: "Output text for round trip",
				Attributes: map[string]string{
					"attr1": "val1",
					"attr2": "val2",
				},
			},
		},
		{
			name:    "empty request round trip",
			request: &EvaluationRequest{},
		},
		{
			name: "minimal request round trip",
			request: &EvaluationRequest{
				TenantID: "tenant-minimal",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to proto
			protoCtx := tt.request.ToProtoContext()
			require.NotNil(t, protoCtx)

			// Convert back
			result := FromProtoContext(protoCtx)
			require.NotNil(t, result)

			// Verify all fields match
			assert.Equal(t, tt.request.TenantID, result.TenantID)
			assert.Equal(t, tt.request.UserID, result.UserID)
			assert.Equal(t, tt.request.WorkflowID, result.WorkflowID)
			assert.Equal(t, tt.request.EnvelopeID, result.EnvelopeID)
			assert.Equal(t, tt.request.Phase, result.Phase)
			assert.Equal(t, tt.request.ModelID, result.ModelID)
			assert.Equal(t, tt.request.InputText, result.InputText)
			assert.Equal(t, tt.request.OutputText, result.OutputText)

			// Handle nil vs empty slice comparison
			if tt.request.UserRoles == nil {
				assert.Nil(t, result.UserRoles)
			} else {
				assert.Equal(t, tt.request.UserRoles, result.UserRoles)
			}

			if tt.request.ToolNames == nil {
				assert.Nil(t, result.ToolNames)
			} else {
				assert.Equal(t, tt.request.ToolNames, result.ToolNames)
			}

			if tt.request.Attributes == nil {
				assert.Nil(t, result.Attributes)
			} else {
				assert.Equal(t, tt.request.Attributes, result.Attributes)
			}
		})
	}
}

func TestDecision_Struct(t *testing.T) {
	// Test that Decision struct can be properly constructed and used
	t.Run("create decision with all fields", func(t *testing.T) {
		policy := &Policy{
			PolicyId: "test-policy",
			Name:     "Test Policy",
		}

		actions := []*PolicyAction{
			{
				ActionType: PolicyActionType_ACTION_TYPE_DENY,
				Message:    "Access denied",
			},
		}

		decision := Decision{
			Action:        ActionDeny,
			MatchedPolicy: policy,
			MatchedRules: []*RuleMatch{
				{
					RuleID:   "rule-1",
					RuleName: "Test Rule",
					Priority: 100,
				},
			},
			Actions:              actions,
			Reason:               "User not authorized",
			EvaluationDurationMs: 5,
			EscalationReason:     "",
		}

		assert.Equal(t, ActionDeny, decision.Action)
		assert.Equal(t, "test-policy", decision.MatchedPolicy.PolicyId)
		assert.Len(t, decision.MatchedRules, 1)
		assert.Equal(t, "rule-1", decision.MatchedRules[0].RuleID)
		assert.Len(t, decision.Actions, 1)
		assert.Equal(t, "User not authorized", decision.Reason)
		assert.Equal(t, int64(5), decision.EvaluationDurationMs)
		assert.Empty(t, decision.EscalationReason)
	})

	t.Run("create decision with escalation", func(t *testing.T) {
		decision := Decision{
			Action:           ActionEscalate,
			Reason:           "Requires semantic analysis",
			EscalationReason: "Content flagged for review by Semantic Judge",
		}

		assert.Equal(t, ActionEscalate, decision.Action)
		assert.Equal(t, "escalate", decision.Action.String())
		assert.Equal(t, "Content flagged for review by Semantic Judge", decision.EscalationReason)
	})

	t.Run("create decision with nil fields", func(t *testing.T) {
		decision := Decision{
			Action: ActionAllow,
		}

		assert.Equal(t, ActionAllow, decision.Action)
		assert.Nil(t, decision.MatchedPolicy)
		assert.Nil(t, decision.MatchedRules)
		assert.Nil(t, decision.Actions)
		assert.Empty(t, decision.Reason)
	})
}

func TestRuleMatch_Struct(t *testing.T) {
	t.Run("create rule match", func(t *testing.T) {
		match := RuleMatch{
			RuleID:   "rule-abc-123",
			RuleName: "Content Filter Rule",
			Priority: 50,
		}

		assert.Equal(t, "rule-abc-123", match.RuleID)
		assert.Equal(t, "Content Filter Rule", match.RuleName)
		assert.Equal(t, int32(50), match.Priority)
	})

	t.Run("create rule match with zero priority", func(t *testing.T) {
		match := RuleMatch{
			RuleID:   "rule-zero",
			RuleName: "Default Rule",
			Priority: 0,
		}

		assert.Equal(t, int32(0), match.Priority)
	})

	t.Run("create rule match with negative priority", func(t *testing.T) {
		match := RuleMatch{
			RuleID:   "rule-negative",
			RuleName: "Override Rule",
			Priority: -10,
		}

		assert.Equal(t, int32(-10), match.Priority)
	})
}

func TestActionType_Values(t *testing.T) {
	// Verify the const values are what we expect
	t.Run("verify action type values", func(t *testing.T) {
		assert.Equal(t, ActionType(0), ActionAllow)
		assert.Equal(t, ActionType(1), ActionDeny)
		assert.Equal(t, ActionType(2), ActionEscalate)
		assert.Equal(t, ActionType(3), ActionWarn)
		assert.Equal(t, ActionType(4), ActionRequireApproval)
	})

	t.Run("verify all known actions have distinct strings", func(t *testing.T) {
		actions := []ActionType{
			ActionAllow,
			ActionDeny,
			ActionEscalate,
			ActionWarn,
			ActionRequireApproval,
		}

		seen := make(map[string]bool)
		for _, action := range actions {
			str := action.String()
			assert.NotEqual(t, "unknown", str, "Known action should not return unknown")
			assert.False(t, seen[str], "Each action should have unique string: %s", str)
			seen[str] = true
		}
	})
}

func TestEvaluationRequest_Attributes(t *testing.T) {
	t.Run("attributes with empty string values", func(t *testing.T) {
		req := &EvaluationRequest{
			Attributes: map[string]string{
				"empty_value": "",
				"normal":      "value",
			},
		}

		ctx := req.ToProtoContext()
		assert.Equal(t, "", ctx.Attributes["empty_value"])
		assert.Equal(t, "value", ctx.Attributes["normal"])
	})

	t.Run("attributes with empty string keys", func(t *testing.T) {
		req := &EvaluationRequest{
			Attributes: map[string]string{
				"":       "value_for_empty_key",
				"normal": "value",
			},
		}

		ctx := req.ToProtoContext()
		assert.Equal(t, "value_for_empty_key", ctx.Attributes[""])
		assert.Equal(t, "value", ctx.Attributes["normal"])
	})
}
