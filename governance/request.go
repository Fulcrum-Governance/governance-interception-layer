package governance

import "time"

// TransportType identifies the protocol used for the tool invocation.
type TransportType string

const (
	TransportMCP      TransportType = "mcp"
	TransportCLI      TransportType = "cli"
	TransportCodeExec TransportType = "code_exec"
	TransportGRPC     TransportType = "grpc"
	TransportA2A      TransportType = "a2a"
	TransportWebhook  TransportType = "webhook"
)

// GovernanceRequest is the canonical, protocol-independent representation
// of an action that must be governed before execution.
type GovernanceRequest struct {
	// Identity
	RequestID string        `json:"request_id"`
	Transport TransportType `json:"transport"`
	AgentID   string        `json:"agent_id"`
	TenantID  string        `json:"tenant_id"`

	// Action being governed
	ToolName   string         `json:"tool_name"`
	Action     string         `json:"action"`
	Arguments  map[string]any `json:"arguments"`
	RawPayload []byte         `json:"raw_payload,omitempty"`

	// CLI-specific fields
	Command   string        `json:"command,omitempty"`
	Stdin     []byte        `json:"stdin,omitempty"`
	PipeChain []PipeSegment `json:"pipe_chain,omitempty"`

	// Code-exec-specific fields
	Code      string `json:"code,omitempty"`
	Language  string `json:"language,omitempty"`
	SandboxID string `json:"sandbox_id,omitempty"`

	// Governance context
	EnvelopeID  string `json:"envelope_id"`
	ParentEnvID string `json:"parent_envelope_id,omitempty"`
	TraceID     string `json:"trace_id"`
	BudgetKey   string `json:"budget_key"`
}

// PipeSegment represents a single command in a pipe chain.
type PipeSegment struct {
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	RiskLevel string   `json:"risk_level"` // read, write, admin, destructive
}

// HighestRisk returns the highest risk level across all pipe segments.
// Risk ordering: destructive > admin > write > read.
func HighestRisk(segments []PipeSegment) string {
	order := map[string]int{
		"read":        0,
		"write":       1,
		"admin":       2,
		"destructive": 3,
	}
	highest := "read"
	for _, seg := range segments {
		if order[seg.RiskLevel] > order[highest] {
			highest = seg.RiskLevel
		}
	}
	return highest
}

// GovernanceDecision is the canonical output of the governance pipeline.
type GovernanceDecision struct {
	RequestID    string        `json:"request_id"`
	Action       string        `json:"action"` // allow, deny, warn, escalate, require_approval
	Reason       string        `json:"reason"`
	PolicyID     string        `json:"policy_id,omitempty"`
	TrustScore   float64       `json:"trust_score"`
	EnvelopeID   string        `json:"envelope_id"`
	DryRun       bool          `json:"dry_run"`
	CostEstimate float64       `json:"cost_estimate,omitempty"`
	Duration     time.Duration `json:"duration"`
	// DecisionMode labels the epistemic confidence level of this decision:
	// deterministic, classified, proved, or human_approved. Empty string
	// means the producer did not label the mode (backwards compat).
	DecisionMode DecisionMode `json:"decision_mode,omitempty"`
}

// Allowed returns true if the decision permits execution.
func (d *GovernanceDecision) Allowed() bool {
	return d.Action == "allow" || d.Action == "warn"
}

// ToolResponse wraps the result of executing a governed tool call.
type ToolResponse struct {
	Content     []byte            `json:"content"`
	ContentType string            `json:"content_type"`
	ExitCode    int               `json:"exit_code,omitempty"`
	Duration    time.Duration     `json:"duration"`
	Truncated   bool              `json:"truncated"`
	FilePath    string            `json:"file_path,omitempty"`
	Metadata    map[string]string `json:"metadata"`
}

// ResponseInspection holds the results of post-execution response analysis.
type ResponseInspection struct {
	Safe            bool     `json:"safe"`
	Concerns        []string `json:"concerns,omitempty"`
	InjectionRisk   float64  `json:"injection_risk"`
	SensitiveData   bool     `json:"sensitive_data"`
	ComplianceFlags []string `json:"compliance_flags,omitempty"`
}
