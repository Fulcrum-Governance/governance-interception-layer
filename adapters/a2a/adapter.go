// Package a2a provides a TransportAdapter for Google's Agent-to-Agent
// (A2A) protocol. The protocol is still evolving; this adapter parses
// task messages into a canonical GovernanceRequest using a minimal local
// schema. Forwarding remains the caller's responsibility — the adapter
// only governs the decision step.
package a2a

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/fulcrum-governance/gil/governance"
)

// TaskMessage is a minimal local schema for an A2A task message,
// modeled on the public Agent-to-Agent protocol shape.
type TaskMessage struct {
	TaskID    string         `json:"task_id"`
	AgentCard AgentCard      `json:"agent_card"`
	Action    string         `json:"action"`
	Input     map[string]any `json:"input"`
}

// AgentCard identifies an A2A participant.
type AgentCard struct {
	AgentID  string `json:"agent_id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

// Adapter implements governance.TransportAdapter for A2A messages.
type Adapter struct {
	// TenantID is applied to every parsed request when the inbound
	// message does not carry tenant information of its own.
	TenantID string
}

// NewAdapter returns an A2A adapter scoped to a tenant.
func NewAdapter(tenantID string) *Adapter {
	return &Adapter{TenantID: tenantID}
}

// Type returns TransportA2A.
func (a *Adapter) Type() governance.TransportType { return governance.TransportA2A }

// ParseRequest accepts *TaskMessage, TaskMessage, or a JSON byte slice.
// It returns an error for any other input shape or for missing required fields.
func (a *Adapter) ParseRequest(_ context.Context, raw any) (*governance.GovernanceRequest, error) {
	var msg *TaskMessage
	switch v := raw.(type) {
	case *TaskMessage:
		msg = v
	case TaskMessage:
		msg = &v
	case json.RawMessage:
		msg = &TaskMessage{}
		if err := json.Unmarshal(v, msg); err != nil {
			return nil, governance.NewParseError(governance.TransportA2A, "unmarshal task message", err)
		}
	case []byte:
		msg = &TaskMessage{}
		if err := json.Unmarshal(v, msg); err != nil {
			return nil, governance.NewParseError(governance.TransportA2A, "unmarshal task message", err)
		}
	default:
		return nil, governance.NewParseError(governance.TransportA2A, fmt.Sprintf("unsupported raw type %T", raw), nil)
	}
	if msg == nil || msg.Action == "" {
		return nil, governance.NewParseError(governance.TransportA2A, "TaskMessage.Action is required", nil)
	}

	traceID := msg.TaskID
	return &governance.GovernanceRequest{
		RequestID: uuid.New().String(),
		Transport: governance.TransportA2A,
		AgentID:   msg.AgentCard.AgentID,
		TenantID:  a.TenantID,
		ToolName:  msg.Action,
		Action:    "a2a/task",
		Arguments: msg.Input,
		TraceID:   traceID,
	}, nil
}

// ForwardGoverned is a no-op. A2A forwarding is the caller's job; this
// adapter only governs the decision.
func (a *Adapter) ForwardGoverned(_ context.Context, _ *governance.GovernanceRequest, _ *governance.GovernanceDecision) (*governance.ToolResponse, error) {
	return nil, nil
}

// InspectResponse is a no-op for A2A.
func (a *Adapter) InspectResponse(_ context.Context, _ *governance.ToolResponse) (*governance.ResponseInspection, error) {
	return nil, nil
}

// EmitGovernanceMetadata is a no-op for A2A.
func (a *Adapter) EmitGovernanceMetadata(_ context.Context, _ *governance.ToolResponse, _ *governance.GovernanceDecision) error {
	return nil
}
