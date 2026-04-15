package governance

import "context"

// TransportAdapter converts between a protocol-specific format and the
// canonical GovernanceRequest / GovernanceDecision types.
type TransportAdapter interface {
	// Type returns the transport type this adapter handles.
	Type() TransportType

	// ParseRequest converts protocol-specific input to a GovernanceRequest.
	ParseRequest(ctx context.Context, raw any) (*GovernanceRequest, error)

	// ForwardGoverned sends the governed request to the downstream tool.
	ForwardGoverned(ctx context.Context, req *GovernanceRequest, decision *GovernanceDecision) (*ToolResponse, error)

	// InspectResponse examines tool output for governance concerns.
	InspectResponse(ctx context.Context, resp *ToolResponse) (*ResponseInspection, error)

	// EmitGovernanceMetadata attaches governance info to the response.
	EmitGovernanceMetadata(ctx context.Context, resp *ToolResponse, decision *GovernanceDecision) error
}
