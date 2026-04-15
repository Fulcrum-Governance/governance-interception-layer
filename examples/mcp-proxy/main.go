// Example: governance for an MCP JSON-RPC tools/call payload.
//
// The MCP adapter parses a raw JSON-RPC params blob into a canonical
// GovernanceRequest, then the shared pipeline evaluates it. In a real MCP
// proxy, ForwardGoverned would relay the approved request upstream; here we
// just print the decision.
//
// Run with: go run main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fulcrum-governance/gil/adapters/mcp"
	"github.com/fulcrum-governance/gil/governance"
)

func main() {
	cfg := governance.PipelineConfig{
		StaticPolicies: []governance.StaticPolicyRule{
			{Name: "block-shell", Tool: "shell_exec", Action: "deny", Reason: "shell_exec is not governed"},
		},
	}
	pipeline := governance.NewPipeline(cfg, nil, nil, nil)
	adapter := mcp.NewAdapter("default-tenant")

	// A mock MCP tools/call payload — the shape the proxy would receive.
	rawPayloads := [][]byte{
		[]byte(`{"tool_name":"read_file","arguments":{"path":"/etc/hosts"},"agent_id":"agent-A","tenant_id":"acme"}`),
		[]byte(`{"tool_name":"shell_exec","arguments":{"cmd":"rm -rf /"},"agent_id":"agent-B","tenant_id":"acme"}`),
	}

	for _, raw := range rawPayloads {
		req, err := adapter.ParseRequest(context.Background(), json.RawMessage(raw))
		if err != nil {
			fmt.Printf("parse error: %v\n", err)
			continue
		}
		decision, err := pipeline.Evaluate(context.Background(), req)
		if err != nil {
			fmt.Printf("evaluate error: %v\n", err)
			continue
		}
		fmt.Printf("tool=%s agent=%s tenant=%s → %s (%s)\n",
			req.ToolName, req.AgentID, req.TenantID, decision.Action, decision.Reason)
	}
}
