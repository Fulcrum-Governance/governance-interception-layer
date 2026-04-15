// Example: domain-specific SQL guard interceptor composed with static policy.
//
// Interceptors fire at Stage 3 of the pipeline (AFTER trust + static policy,
// BEFORE the portable PolicyEval engine). They are the right extension point
// for domain logic that cannot be expressed as a declarative rule — in this
// case, inspecting the SQL string before it reaches the database.
//
// Run with: go run main.go
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/fulcrum-governance/gil/governance"
)

func sqlGuard(_ context.Context, req *governance.GovernanceRequest) (*governance.InterceptorResult, error) {
	sql, _ := req.Arguments["sql"].(string)
	upper := strings.ToUpper(sql)
	for _, banned := range []string{"DROP ", "DELETE "} {
		if strings.Contains(upper, banned) {
			return &governance.InterceptorResult{
				Allowed: false,
				Action:  "deny",
				Reason:  fmt.Sprintf("SQL contains banned keyword %q", strings.TrimSpace(banned)),
			}, nil
		}
	}
	return nil, nil // no interception — continue pipeline
}

func main() {
	cfg := governance.PipelineConfig{
		StaticPolicies: []governance.StaticPolicyRule{
			// Static policy denies any tool named "raw_shell", regardless of args.
			{Name: "block-raw-shell", Tool: "raw_shell", Action: "deny", Reason: "raw shell is never allowed"},
		},
	}
	pipeline := governance.NewPipeline(cfg, nil, nil, nil)
	pipeline.RegisterInterceptor("database_query", sqlGuard)

	requests := []*governance.GovernanceRequest{
		{ToolName: "database_query", Transport: governance.TransportMCP, Arguments: map[string]any{"sql": "SELECT id FROM users WHERE tenant = $1"}},
		{ToolName: "database_query", Transport: governance.TransportMCP, Arguments: map[string]any{"sql": "DROP TABLE users"}},
		{ToolName: "database_query", Transport: governance.TransportMCP, Arguments: map[string]any{"sql": "delete from audit_log"}},
		{ToolName: "raw_shell", Transport: governance.TransportCLI, Arguments: map[string]any{"cmd": "ls"}},
	}

	for _, req := range requests {
		decision, err := pipeline.Evaluate(context.Background(), req)
		if err != nil {
			fmt.Printf("[%s] ERROR: %v\n", req.ToolName, err)
			continue
		}
		arg := fmt.Sprintf("%v", req.Arguments)
		if len(arg) > 50 {
			arg = arg[:50] + "..."
		}
		fmt.Printf("[%s] %s — %s | args=%s\n", req.ToolName, decision.Action, decision.Reason, arg)
	}
}
