package policyeval

import (
	"fmt"
	"strings"
)

// EvaluateCondition evaluates a single policy condition against the provided context.
func EvaluateCondition(condition *PolicyCondition, ctx *EvaluationContext, externalCallsEnabled bool) (bool, error) {
	if condition == nil {
		return false, fmt.Errorf("condition is nil")
	}

	// Handle logical conditions (AND/OR/NOT with nested conditions)
	if condition.ConditionType == ConditionType_CONDITION_TYPE_LOGICAL {
		return evaluateLogicalCondition(condition, ctx, externalCallsEnabled)
	}

	// Extract field value from context
	fieldValue, err := extractFieldValue(condition.Field, ctx)
	if err != nil {
		return false, err
	}

	// Evaluate based on condition type
	var result bool
	switch condition.ConditionType {
	case ConditionType_CONDITION_TYPE_FIELD_MATCH:
		result = evaluateFieldMatch(fieldValue, condition)
	case ConditionType_CONDITION_TYPE_REGEX:
		result, err = evaluateRegex(fieldValue, condition)
	case ConditionType_CONDITION_TYPE_RANGE:
		result, err = evaluateRange(fieldValue, condition)
	case ConditionType_CONDITION_TYPE_IN_LIST:
		result = evaluateInList(fieldValue, condition)
	case ConditionType_CONDITION_TYPE_CONTAINS:
		result = evaluateContains(fieldValue, condition)
	case ConditionType_CONDITION_TYPE_STARTS_WITH:
		result = evaluateStartsWith(fieldValue, condition)
	case ConditionType_CONDITION_TYPE_ENDS_WITH:
		result = evaluateEndsWith(fieldValue, condition)
	case ConditionType_CONDITION_TYPE_STATISTICAL_SPIKE:
		result = evaluateStatisticalSpike(fieldValue, condition, ctx)
	case ConditionType_CONDITION_TYPE_EXTERNAL_CALL:
		if !externalCallsEnabled {
			return false, fmt.Errorf("external calls are disabled")
		}
		result, err = evaluateExternalCall(condition, ctx)
	case ConditionType_CONDITION_TYPE_SEMANTIC:
		// Semantic conditions should be handled by escalation, not here
		return false, fmt.Errorf("semantic conditions require escalation to server")
	default:
		return false, fmt.Errorf("unsupported condition type: %v", condition.ConditionType)
	}

	if err != nil {
		return false, err
	}

	// Apply negation if specified
	if condition.Negate {
		result = !result
	}

	return result, nil
}

func evaluateLogicalCondition(condition *PolicyCondition, ctx *EvaluationContext, externalCallsEnabled bool) (bool, error) {
	if len(condition.NestedConditions) == 0 {
		return false, fmt.Errorf("logical condition has no nested conditions")
	}

	switch condition.LogicalOperator {
	case LogicalOperator_LOGICAL_OPERATOR_AND:
		for _, nested := range condition.NestedConditions {
			result, err := EvaluateCondition(nested, ctx, externalCallsEnabled)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
		return true, nil

	case LogicalOperator_LOGICAL_OPERATOR_OR:
		for _, nested := range condition.NestedConditions {
			result, err := EvaluateCondition(nested, ctx, externalCallsEnabled)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil
			}
		}
		return false, nil

	case LogicalOperator_LOGICAL_OPERATOR_NOT:
		if len(condition.NestedConditions) == 0 {
			return false, fmt.Errorf("NOT operator requires exactly one nested condition")
		}
		result, err := EvaluateCondition(condition.NestedConditions[0], ctx, externalCallsEnabled)
		if err != nil {
			return false, err
		}
		return !result, nil

	default:
		return false, fmt.Errorf("unsupported logical operator: %v", condition.LogicalOperator)
	}
}

func extractFieldValue(field string, ctx *EvaluationContext) (string, error) {
	if field == "" {
		return "", fmt.Errorf("field is empty")
	}

	parts := strings.Split(field, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid field format: %s (expected category.name)", field)
	}

	category := parts[0]
	name := parts[1]

	switch category {
	case "user":
		switch name {
		case "id":
			return ctx.UserId, nil
		case "role":
			if len(ctx.UserRoles) > 0 {
				return ctx.UserRoles[0], nil
			}
			return "", nil
		case "roles":
			return strings.Join(ctx.UserRoles, ","), nil
		}

	case "model":
		switch name {
		case "id":
			return ctx.ModelId, nil
		}

	case "tool":
		switch name {
		case "name":
			if len(ctx.ToolNames) > 0 {
				return ctx.ToolNames[0], nil
			}
			return "", nil
		case "names":
			return strings.Join(ctx.ToolNames, ","), nil
		}

	case "workflow":
		switch name {
		case "id":
			return ctx.WorkflowId, nil
		}

	case "tenant":
		switch name {
		case "id":
			return ctx.TenantId, nil
		}

	case "envelope":
		switch name {
		case "id":
			return ctx.EnvelopeId, nil
		}

	case "phase":
		switch name {
		case "type":
			return ctx.Phase.String(), nil
		}

	case "input":
		switch name {
		case "text":
			return ctx.InputText, nil
		}

	case "output":
		switch name {
		case "text":
			return ctx.OutputText, nil
		}

	case "attribute":
		if len(parts) >= 3 {
			attrName := strings.Join(parts[2:], ".")
			if val, ok := ctx.Attributes[attrName]; ok {
				return val, nil
			}
		}
		return "", nil
	}

	return "", fmt.Errorf("unknown field: %s", field)
}
