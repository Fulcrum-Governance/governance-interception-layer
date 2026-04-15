// Package policyeval types.go defines the policy model used by the evaluator.
//
// These types are inlined plain-Go equivalents of the protobuf messages
// previously generated from fulcrum/policy/v1/policy_service.proto.
//
// The GIL evaluates policies locally against these in-memory Go structs. It
// does not require gRPC, protobuf runtime, or wire compatibility with any
// upstream policy service. Consumers construct Policy/Rule/Condition values
// directly in Go.
//
// The proto-generated enum type ActionType was renamed to PolicyActionType
// here to avoid colliding with the local decision-outcome ActionType declared
// in decision.go. Enum constant identifiers keep the "<TypeName>_<VALUE>"
// form so they remain greppable against the original proto schema.
package policyeval

// PolicyStatus is the lifecycle state of a Policy.
type PolicyStatus int32

const (
	PolicyStatus_POLICY_STATUS_UNSPECIFIED PolicyStatus = 0
	PolicyStatus_POLICY_STATUS_DRAFT       PolicyStatus = 1
	PolicyStatus_POLICY_STATUS_ACTIVE      PolicyStatus = 2
	PolicyStatus_POLICY_STATUS_INACTIVE    PolicyStatus = 3
	PolicyStatus_POLICY_STATUS_ARCHIVED    PolicyStatus = 4
)

func (s PolicyStatus) String() string {
	switch s {
	case PolicyStatus_POLICY_STATUS_UNSPECIFIED:
		return "POLICY_STATUS_UNSPECIFIED"
	case PolicyStatus_POLICY_STATUS_DRAFT:
		return "POLICY_STATUS_DRAFT"
	case PolicyStatus_POLICY_STATUS_ACTIVE:
		return "POLICY_STATUS_ACTIVE"
	case PolicyStatus_POLICY_STATUS_INACTIVE:
		return "POLICY_STATUS_INACTIVE"
	case PolicyStatus_POLICY_STATUS_ARCHIVED:
		return "POLICY_STATUS_ARCHIVED"
	default:
		return "POLICY_STATUS_UNSPECIFIED"
	}
}

// ConditionType categorizes how a PolicyCondition is evaluated.
type ConditionType int32

const (
	ConditionType_CONDITION_TYPE_UNSPECIFIED       ConditionType = 0
	ConditionType_CONDITION_TYPE_FIELD_MATCH       ConditionType = 1
	ConditionType_CONDITION_TYPE_REGEX             ConditionType = 2
	ConditionType_CONDITION_TYPE_RANGE             ConditionType = 3
	ConditionType_CONDITION_TYPE_IN_LIST           ConditionType = 4
	ConditionType_CONDITION_TYPE_CONTAINS          ConditionType = 5
	ConditionType_CONDITION_TYPE_STARTS_WITH       ConditionType = 6
	ConditionType_CONDITION_TYPE_ENDS_WITH         ConditionType = 7
	ConditionType_CONDITION_TYPE_LOGICAL           ConditionType = 8
	ConditionType_CONDITION_TYPE_STATISTICAL_SPIKE ConditionType = 9
	ConditionType_CONDITION_TYPE_EXTERNAL_CALL     ConditionType = 10
	ConditionType_CONDITION_TYPE_SEMANTIC          ConditionType = 11
)

func (t ConditionType) String() string {
	switch t {
	case ConditionType_CONDITION_TYPE_UNSPECIFIED:
		return "CONDITION_TYPE_UNSPECIFIED"
	case ConditionType_CONDITION_TYPE_FIELD_MATCH:
		return "CONDITION_TYPE_FIELD_MATCH"
	case ConditionType_CONDITION_TYPE_REGEX:
		return "CONDITION_TYPE_REGEX"
	case ConditionType_CONDITION_TYPE_RANGE:
		return "CONDITION_TYPE_RANGE"
	case ConditionType_CONDITION_TYPE_IN_LIST:
		return "CONDITION_TYPE_IN_LIST"
	case ConditionType_CONDITION_TYPE_CONTAINS:
		return "CONDITION_TYPE_CONTAINS"
	case ConditionType_CONDITION_TYPE_STARTS_WITH:
		return "CONDITION_TYPE_STARTS_WITH"
	case ConditionType_CONDITION_TYPE_ENDS_WITH:
		return "CONDITION_TYPE_ENDS_WITH"
	case ConditionType_CONDITION_TYPE_LOGICAL:
		return "CONDITION_TYPE_LOGICAL"
	case ConditionType_CONDITION_TYPE_STATISTICAL_SPIKE:
		return "CONDITION_TYPE_STATISTICAL_SPIKE"
	case ConditionType_CONDITION_TYPE_EXTERNAL_CALL:
		return "CONDITION_TYPE_EXTERNAL_CALL"
	case ConditionType_CONDITION_TYPE_SEMANTIC:
		return "CONDITION_TYPE_SEMANTIC"
	default:
		return "CONDITION_TYPE_UNSPECIFIED"
	}
}

// ConditionOperator is the comparison applied in a PolicyCondition.
type ConditionOperator int32

const (
	ConditionOperator_CONDITION_OPERATOR_UNSPECIFIED   ConditionOperator = 0
	ConditionOperator_CONDITION_OPERATOR_EQUALS        ConditionOperator = 1
	ConditionOperator_CONDITION_OPERATOR_NOT_EQUALS    ConditionOperator = 2
	ConditionOperator_CONDITION_OPERATOR_GREATER_THAN  ConditionOperator = 3
	ConditionOperator_CONDITION_OPERATOR_LESS_THAN     ConditionOperator = 4
	ConditionOperator_CONDITION_OPERATOR_GREATER_EQUAL ConditionOperator = 5
	ConditionOperator_CONDITION_OPERATOR_LESS_EQUAL    ConditionOperator = 6
	ConditionOperator_CONDITION_OPERATOR_MATCHES       ConditionOperator = 7
	ConditionOperator_CONDITION_OPERATOR_CONTAINS      ConditionOperator = 8
	ConditionOperator_CONDITION_OPERATOR_IN            ConditionOperator = 9
	ConditionOperator_CONDITION_OPERATOR_NOT_IN        ConditionOperator = 10
)

func (o ConditionOperator) String() string {
	switch o {
	case ConditionOperator_CONDITION_OPERATOR_UNSPECIFIED:
		return "CONDITION_OPERATOR_UNSPECIFIED"
	case ConditionOperator_CONDITION_OPERATOR_EQUALS:
		return "CONDITION_OPERATOR_EQUALS"
	case ConditionOperator_CONDITION_OPERATOR_NOT_EQUALS:
		return "CONDITION_OPERATOR_NOT_EQUALS"
	case ConditionOperator_CONDITION_OPERATOR_GREATER_THAN:
		return "CONDITION_OPERATOR_GREATER_THAN"
	case ConditionOperator_CONDITION_OPERATOR_LESS_THAN:
		return "CONDITION_OPERATOR_LESS_THAN"
	case ConditionOperator_CONDITION_OPERATOR_GREATER_EQUAL:
		return "CONDITION_OPERATOR_GREATER_EQUAL"
	case ConditionOperator_CONDITION_OPERATOR_LESS_EQUAL:
		return "CONDITION_OPERATOR_LESS_EQUAL"
	case ConditionOperator_CONDITION_OPERATOR_MATCHES:
		return "CONDITION_OPERATOR_MATCHES"
	case ConditionOperator_CONDITION_OPERATOR_CONTAINS:
		return "CONDITION_OPERATOR_CONTAINS"
	case ConditionOperator_CONDITION_OPERATOR_IN:
		return "CONDITION_OPERATOR_IN"
	case ConditionOperator_CONDITION_OPERATOR_NOT_IN:
		return "CONDITION_OPERATOR_NOT_IN"
	default:
		return "CONDITION_OPERATOR_UNSPECIFIED"
	}
}

// LogicalOperator combines nested PolicyConditions.
type LogicalOperator int32

const (
	LogicalOperator_LOGICAL_OPERATOR_UNSPECIFIED LogicalOperator = 0
	LogicalOperator_LOGICAL_OPERATOR_AND         LogicalOperator = 1
	LogicalOperator_LOGICAL_OPERATOR_OR          LogicalOperator = 2
	LogicalOperator_LOGICAL_OPERATOR_NOT         LogicalOperator = 3
)

func (o LogicalOperator) String() string {
	switch o {
	case LogicalOperator_LOGICAL_OPERATOR_UNSPECIFIED:
		return "LOGICAL_OPERATOR_UNSPECIFIED"
	case LogicalOperator_LOGICAL_OPERATOR_AND:
		return "LOGICAL_OPERATOR_AND"
	case LogicalOperator_LOGICAL_OPERATOR_OR:
		return "LOGICAL_OPERATOR_OR"
	case LogicalOperator_LOGICAL_OPERATOR_NOT:
		return "LOGICAL_OPERATOR_NOT"
	default:
		return "LOGICAL_OPERATOR_UNSPECIFIED"
	}
}

// PolicyActionType declares the action a matched PolicyRule takes.
//
// Named PolicyActionType (rather than ActionType) to avoid collision with the
// local decision-outcome ActionType in decision.go.
type PolicyActionType int32

const (
	PolicyActionType_ACTION_TYPE_UNSPECIFIED      PolicyActionType = 0
	PolicyActionType_ACTION_TYPE_ALLOW            PolicyActionType = 1
	PolicyActionType_ACTION_TYPE_DENY             PolicyActionType = 2
	PolicyActionType_ACTION_TYPE_WARN             PolicyActionType = 3
	PolicyActionType_ACTION_TYPE_MODIFY           PolicyActionType = 4
	PolicyActionType_ACTION_TYPE_REDIRECT         PolicyActionType = 5
	PolicyActionType_ACTION_TYPE_AUDIT            PolicyActionType = 6
	PolicyActionType_ACTION_TYPE_THROTTLE         PolicyActionType = 7
	PolicyActionType_ACTION_TYPE_REQUIRE_APPROVAL PolicyActionType = 8
	PolicyActionType_ACTION_TYPE_NOTIFY           PolicyActionType = 9
)

func (a PolicyActionType) String() string {
	switch a {
	case PolicyActionType_ACTION_TYPE_UNSPECIFIED:
		return "ACTION_TYPE_UNSPECIFIED"
	case PolicyActionType_ACTION_TYPE_ALLOW:
		return "ACTION_TYPE_ALLOW"
	case PolicyActionType_ACTION_TYPE_DENY:
		return "ACTION_TYPE_DENY"
	case PolicyActionType_ACTION_TYPE_WARN:
		return "ACTION_TYPE_WARN"
	case PolicyActionType_ACTION_TYPE_MODIFY:
		return "ACTION_TYPE_MODIFY"
	case PolicyActionType_ACTION_TYPE_REDIRECT:
		return "ACTION_TYPE_REDIRECT"
	case PolicyActionType_ACTION_TYPE_AUDIT:
		return "ACTION_TYPE_AUDIT"
	case PolicyActionType_ACTION_TYPE_THROTTLE:
		return "ACTION_TYPE_THROTTLE"
	case PolicyActionType_ACTION_TYPE_REQUIRE_APPROVAL:
		return "ACTION_TYPE_REQUIRE_APPROVAL"
	case PolicyActionType_ACTION_TYPE_NOTIFY:
		return "ACTION_TYPE_NOTIFY"
	default:
		return "ACTION_TYPE_UNSPECIFIED"
	}
}

// ExecutionPhase declares when during an agent's lifecycle a policy is evaluated.
type ExecutionPhase int32

const (
	ExecutionPhase_EXECUTION_PHASE_UNSPECIFIED    ExecutionPhase = 0
	ExecutionPhase_EXECUTION_PHASE_PRE_EXECUTION  ExecutionPhase = 1
	ExecutionPhase_EXECUTION_PHASE_PRE_LLM_CALL   ExecutionPhase = 2
	ExecutionPhase_EXECUTION_PHASE_POST_LLM_CALL  ExecutionPhase = 3
	ExecutionPhase_EXECUTION_PHASE_PRE_TOOL_CALL  ExecutionPhase = 4
	ExecutionPhase_EXECUTION_PHASE_POST_TOOL_CALL ExecutionPhase = 5
	ExecutionPhase_EXECUTION_PHASE_POST_EXECUTION ExecutionPhase = 6
)

func (p ExecutionPhase) String() string {
	switch p {
	case ExecutionPhase_EXECUTION_PHASE_UNSPECIFIED:
		return "EXECUTION_PHASE_UNSPECIFIED"
	case ExecutionPhase_EXECUTION_PHASE_PRE_EXECUTION:
		return "EXECUTION_PHASE_PRE_EXECUTION"
	case ExecutionPhase_EXECUTION_PHASE_PRE_LLM_CALL:
		return "EXECUTION_PHASE_PRE_LLM_CALL"
	case ExecutionPhase_EXECUTION_PHASE_POST_LLM_CALL:
		return "EXECUTION_PHASE_POST_LLM_CALL"
	case ExecutionPhase_EXECUTION_PHASE_PRE_TOOL_CALL:
		return "EXECUTION_PHASE_PRE_TOOL_CALL"
	case ExecutionPhase_EXECUTION_PHASE_POST_TOOL_CALL:
		return "EXECUTION_PHASE_POST_TOOL_CALL"
	case ExecutionPhase_EXECUTION_PHASE_POST_EXECUTION:
		return "EXECUTION_PHASE_POST_EXECUTION"
	default:
		return "EXECUTION_PHASE_UNSPECIFIED"
	}
}

// Policy is a governance rule set that applies to an agent workflow.
type Policy struct {
	PolicyId    string
	TenantId    string
	Name        string
	Description string
	Rules       []*PolicyRule
	Scope       *PolicyScope
	Status      PolicyStatus
	Priority    int32
}

// PolicyRule is a single rule within a Policy. All conditions AND together;
// the rule triggers the listed actions when every condition matches.
type PolicyRule struct {
	RuleId      string
	Name        string
	Description string
	Conditions  []*PolicyCondition
	Actions     []*PolicyAction
	Enabled     bool
	Priority    int32
}

// PolicyCondition is a single boolean check against an EvaluationContext.
//
// The Value field is a oneof — assign one of *PolicyCondition_StringValue,
// *PolicyCondition_IntValue, *PolicyCondition_FloatValue, or
// *PolicyCondition_BoolValue. Values (plural) is for multi-value IN/NOT_IN
// operators. NestedConditions is for LOGICAL conditions.
type PolicyCondition struct {
	ConditionType               ConditionType
	Field                       string
	Operator                    ConditionOperator
	Value                       isPolicyCondition_Value
	Values                      []string
	NestedConditions            []*PolicyCondition
	LogicalOperator             LogicalOperator
	Negate                      bool
	SemanticIntent              string  // Human-readable intent, used by SEMANTIC conditions (escalated).
	SemanticModel               string  // Optional LLM model hint for semantic evaluation.
	SemanticConfidenceThreshold float32 // Minimum confidence for a semantic match.
}

// isPolicyCondition_Value is the sealed interface implemented by the
// PolicyCondition_*Value wrappers. The original protobuf one-of mechanic.
type isPolicyCondition_Value interface {
	isPolicyCondition_Value()
}

// PolicyCondition_StringValue carries a string comparand for a condition.
type PolicyCondition_StringValue struct {
	StringValue string
}

// PolicyCondition_IntValue carries an int64 comparand for a condition.
type PolicyCondition_IntValue struct {
	IntValue int64
}

// PolicyCondition_FloatValue carries a float64 comparand for a condition.
type PolicyCondition_FloatValue struct {
	FloatValue float64
}

// PolicyCondition_BoolValue carries a bool comparand for a condition.
type PolicyCondition_BoolValue struct {
	BoolValue bool
}

func (*PolicyCondition_StringValue) isPolicyCondition_Value() {}
func (*PolicyCondition_IntValue) isPolicyCondition_Value()    {}
func (*PolicyCondition_FloatValue) isPolicyCondition_Value()  {}
func (*PolicyCondition_BoolValue) isPolicyCondition_Value()   {}

// PolicyAction is the directive emitted when a PolicyRule matches.
type PolicyAction struct {
	ActionType PolicyActionType
	Parameters map[string]string
	Message    string
	Terminal   bool
}

// PolicyScope narrows which EvaluationContexts a Policy applies to.
// An empty scope (or ApplyToAll=true) matches every context.
type PolicyScope struct {
	WorkflowIds []string
	Phases      []ExecutionPhase
	Roles       []string
	ModelIds    []string
	ToolNames   []string
	ApplyToAll  bool
}

// EvaluationContext is the runtime data the evaluator matches rules against.
type EvaluationContext struct {
	TenantId   string
	WorkflowId string
	EnvelopeId string
	UserId     string
	UserRoles  []string
	Phase      ExecutionPhase
	ModelId    string
	ToolNames  []string
	InputText  string
	OutputText string
	Attributes map[string]string
}
