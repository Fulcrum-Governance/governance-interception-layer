package codeexec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fulcrum-governance/gil/governance"
	"github.com/google/uuid"
)

// Verify Adapter implements governance.TransportAdapter at compile time.
var _ governance.TransportAdapter = (*Adapter)(nil)

// CodeExecInput is the protocol-specific input for code execution requests.
type CodeExecInput struct {
	Code      string `json:"code"`
	Language  string `json:"language"` // "python", "javascript", "typescript", "bash"
	SandboxID string `json:"sandbox_id,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// Adapter implements governance.TransportAdapter for code execution requests.
type Adapter struct {
	defaultTenantID string
	analyzers       map[string]Analyzer
}

// NewAdapter creates a code-execution transport adapter. If defaultTenantID is
// non-empty it is used when the incoming request omits a tenant ID.
func NewAdapter(defaultTenantID string) *Adapter {
	return &Adapter{
		defaultTenantID: defaultTenantID,
		analyzers: map[string]Analyzer{
			"python":     &PythonAnalyzer{},
			"javascript": &JSAnalyzer{},
			"typescript": &JSAnalyzer{},
		},
	}
}

// Type returns TransportCodeExec.
func (a *Adapter) Type() governance.TransportType {
	return governance.TransportCodeExec
}

// ParseRequest converts a code-execution input into a canonical
// GovernanceRequest. The raw parameter must be a *CodeExecInput,
// CodeExecInput, json.RawMessage, or []byte.
func (a *Adapter) ParseRequest(_ context.Context, raw any) (*governance.GovernanceRequest, error) {
	var input *CodeExecInput

	switch v := raw.(type) {
	case *CodeExecInput:
		input = v
	case CodeExecInput:
		input = &v
	case json.RawMessage:
		input = &CodeExecInput{}
		if err := json.Unmarshal(v, input); err != nil {
			return nil, governance.NewParseError(governance.TransportCodeExec, "unmarshal input", err)
		}
	case []byte:
		input = &CodeExecInput{}
		if err := json.Unmarshal(v, input); err != nil {
			return nil, governance.NewParseError(governance.TransportCodeExec, "unmarshal input", err)
		}
	default:
		return nil, governance.NewParseError(governance.TransportCodeExec, fmt.Sprintf("unsupported raw type %T", raw), nil)
	}

	if input.Code == "" {
		return nil, governance.NewParseError(governance.TransportCodeExec, "code field is required", nil)
	}
	if input.Language == "" {
		return nil, governance.NewParseError(governance.TransportCodeExec, "language field is required", nil)
	}

	tenantID := input.TenantID
	if tenantID == "" {
		tenantID = a.defaultTenantID
	}

	// Select the language-specific analyser.
	lang := strings.ToLower(input.Language)
	analyzer, ok := a.analyzers[lang]

	var ops []Operation
	if ok {
		ops = analyzer.Analyze(input.Code)
	}

	action := HighestOperationRisk(ops)

	return &governance.GovernanceRequest{
		RequestID: uuid.New().String(),
		Transport: governance.TransportCodeExec,
		AgentID:   input.AgentID,
		TenantID:  tenantID,
		ToolName:  "code_exec",
		Action:    action,
		Code:      input.Code,
		Language:  lang,
		SandboxID: input.SandboxID,
	}, nil
}

// ForwardGoverned is a stub — actual code execution is handled by the sandbox
// runtime. The adapter only provides the parsing/inspection layer.
func (a *Adapter) ForwardGoverned(_ context.Context, _ *governance.GovernanceRequest, _ *governance.GovernanceDecision) (*governance.ToolResponse, error) {
	return nil, fmt.Errorf("code-exec forwarding is handled by the sandbox runtime")
}

// maxSafeOutputSize is the threshold above which a response is flagged.
const maxSafeOutputSize = 50 * 1024 // 50 KB

// sensitivePatterns are substrings that, if found in the response content,
// trigger a sensitive-data concern.
var sensitivePatterns = []string{
	"BEGIN RSA PRIVATE KEY",
	"BEGIN PRIVATE KEY",
	"BEGIN EC PRIVATE KEY",
	"AKIA",           // AWS access key prefix
	"password",       // generic
	"secret_key",     // generic
	"api_key",        // generic
	"Authorization:", // HTTP header
	"Bearer ",        // OAuth token prefix
}

// InspectResponse examines code-execution output for governance concerns.
func (a *Adapter) InspectResponse(_ context.Context, resp *governance.ToolResponse) (*governance.ResponseInspection, error) {
	if resp == nil {
		return &governance.ResponseInspection{Safe: true}, nil
	}

	inspection := &governance.ResponseInspection{
		Safe: true,
	}

	// Check output size.
	if int64(len(resp.Content)) > maxSafeOutputSize {
		inspection.Concerns = append(inspection.Concerns,
			fmt.Sprintf("output size %d bytes exceeds %d byte limit", len(resp.Content), maxSafeOutputSize))
		inspection.Safe = false
	}

	// Check for sensitive data patterns.
	content := string(resp.Content)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(content, pattern) {
			inspection.SensitiveData = true
			inspection.Safe = false
			inspection.Concerns = append(inspection.Concerns,
				fmt.Sprintf("potential sensitive data detected: %q pattern found", pattern))
			break
		}
	}

	// Non-zero exit code is a concern (might indicate attempted privilege escalation).
	if resp.ExitCode != 0 {
		inspection.Concerns = append(inspection.Concerns,
			fmt.Sprintf("non-zero exit code: %d", resp.ExitCode))
	}

	return inspection, nil
}

// EmitGovernanceMetadata attaches governance and code-exec specific metadata
// to the tool response.
func (a *Adapter) EmitGovernanceMetadata(_ context.Context, resp *governance.ToolResponse, decision *governance.GovernanceDecision) error {
	if resp == nil || decision == nil {
		return nil
	}
	if resp.Metadata == nil {
		resp.Metadata = make(map[string]string)
	}
	resp.Metadata["x-fulcrum-action"] = decision.Action
	resp.Metadata["x-fulcrum-envelope-id"] = decision.EnvelopeID
	resp.Metadata["x-fulcrum-request-id"] = decision.RequestID
	resp.Metadata["x-fulcrum-transport"] = string(governance.TransportCodeExec)
	return nil
}
