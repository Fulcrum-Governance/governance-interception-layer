// Example: minimal GIL pipeline with two static policy rules.
//
// Run with: go run main.go
package main

import (
	"context"
	"fmt"

	"github.com/fulcrum-governance/gil/governance"
)

func main() {
	cfg := governance.PipelineConfig{
		StaticPolicies: []governance.StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive filesystem op"},
			{Name: "allow-read", Tool: "read_file", Action: "allow"},
		},
	}
	pipeline := governance.NewPipeline(cfg, nil, nil, nil)

	requests := []*governance.GovernanceRequest{
		{ToolName: "read_file", Transport: governance.TransportMCP, TenantID: "tenant-1"},
		{ToolName: "rm", Transport: governance.TransportCLI, TenantID: "tenant-1"},
		{ToolName: "grep", Transport: governance.TransportCLI, TenantID: "tenant-1"},
	}

	for _, req := range requests {
		decision, err := pipeline.Evaluate(context.Background(), req)
		if err != nil {
			fmt.Printf("[%s] ERROR: %v\n", req.ToolName, err)
			continue
		}
		reason := decision.Reason
		if reason == "" {
			reason = "(no matching rule — default allow)"
		}
		fmt.Printf("[%s] %s — %s\n", req.ToolName, decision.Action, reason)
	}
}
