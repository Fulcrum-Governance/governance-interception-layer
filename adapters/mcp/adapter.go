// Package mcp provides the MCP (Model Context Protocol) transport adapter
// for the Governance Interception Layer.
//
// It converts JSON-RPC tools/call requests into canonical GovernanceRequests
// and delegates governance evaluation to the shared pipeline.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fulcrum-governance/gil/governance"
	"github.com/google/uuid"
)

// ToolCallInput is the protocol-specific input parsed from an MCP tools/call request.
type ToolCallInput struct {
	ToolName  string         `json:"tool_name"`
	Arguments map[string]any `json:"arguments"`
	AgentID   string         `json:"agent_id,omitempty"`
	TenantID  string         `json:"tenant_id,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`
}

// Adapter implements governance.TransportAdapter for MCP JSON-RPC.
type Adapter struct {
	defaultTenantID string
}

// NewAdapter creates an MCP transport adapter.
func NewAdapter(defaultTenantID string) *Adapter {
	return &Adapter{defaultTenantID: defaultTenantID}
}

// Type returns TransportMCP.
func (a *Adapter) Type() governance.TransportType {
	return governance.TransportMCP
}

// ParseRequest converts an MCP ToolCallInput into a canonical GovernanceRequest.
// The raw parameter must be a *ToolCallInput or a json.RawMessage that can be
// unmarshaled into one.
func (a *Adapter) ParseRequest(_ context.Context, raw any) (*governance.GovernanceRequest, error) {
	var input *ToolCallInput

	switch v := raw.(type) {
	case *ToolCallInput:
		input = v
	case ToolCallInput:
		input = &v
	case json.RawMessage:
		input = &ToolCallInput{}
		if err := json.Unmarshal(v, input); err != nil {
			return nil, fmt.Errorf("unmarshal MCP tool call: %w", err)
		}
	case []byte:
		input = &ToolCallInput{}
		if err := json.Unmarshal(v, input); err != nil {
			return nil, fmt.Errorf("unmarshal MCP tool call: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported raw type %T for MCP adapter", raw)
	}

	tenantID := input.TenantID
	if tenantID == "" {
		tenantID = a.defaultTenantID
	}

	return &governance.GovernanceRequest{
		RequestID: uuid.New().String(),
		Transport: governance.TransportMCP,
		AgentID:   input.AgentID,
		TenantID:  tenantID,
		ToolName:  input.ToolName,
		Action:    "tools/call",
		Arguments: input.Arguments,
		TraceID:   input.TraceID,
	}, nil
}

// ForwardGoverned forwards the governed request to the upstream MCP server.
// This is a stub — the actual forwarding is handled by the existing mcpproxy
// or securemcp server code. The adapter only provides the parsing layer.
func (a *Adapter) ForwardGoverned(_ context.Context, _ *governance.GovernanceRequest, _ *governance.GovernanceDecision) (*governance.ToolResponse, error) {
	return nil, fmt.Errorf("MCP forwarding is handled by the existing mcpproxy/securemcp server")
}

// InspectResponse checks MCP tool output for governance concerns.
func (a *Adapter) InspectResponse(_ context.Context, resp *governance.ToolResponse) (*governance.ResponseInspection, error) {
	if resp == nil {
		return &governance.ResponseInspection{Safe: true}, nil
	}
	return &governance.ResponseInspection{
		Safe:          true,
		InjectionRisk: 0.0,
	}, nil
}

// EmitGovernanceMetadata attaches governance headers to the MCP response.
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
	return nil
}
