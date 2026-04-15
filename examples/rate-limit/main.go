// Example: token bucket rate limiting as a governance interceptor.
//
// Registers a RateLimiter allowing 5 requests per 10 seconds per agent.
// Sends 8 rapid requests for the same agent+tool — the first 5 are
// allowed, the remaining 3 are denied with a rate-limit reason. After
// a short sleep the bucket has partially refilled and a ninth request
// is allowed.
//
// Run with: go run main.go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/fulcrum-governance/gil/governance"
	"github.com/fulcrum-governance/gil/interceptors"
)

func main() {
	pipeline := governance.NewPipeline(governance.PipelineConfig{}, nil, nil, nil)

	rl := interceptors.NewRateLimiter(interceptors.RateLimitConfig{
		MaxRequests: 5,
		Window:      10 * time.Second,
	})

	// Register the agent-keyed limiter under the single tool used in this demo.
	// In a real deployment you would register "*" or every tool name you want
	// to rate-limit.
	const toolName = "search"
	pipeline.RegisterInterceptor(toolName, rl.ForAgent())

	send := func(label string) {
		req := &governance.GovernanceRequest{
			Transport: governance.TransportMCP,
			ToolName:  toolName,
			AgentID:   "agent-1",
			TenantID:  "tenant-1",
		}
		decision, err := pipeline.Evaluate(context.Background(), req)
		if err != nil {
			fmt.Printf("[%s] ERROR: %v\n", label, err)
			return
		}
		fmt.Printf("[%s] %s — %s\n", label, decision.Action, decision.Reason)
	}

	fmt.Println("Sending 8 rapid requests (limit: 5 per 10s):")
	for i := 1; i <= 8; i++ {
		send(fmt.Sprintf("req-%d", i))
	}

	// Window/MaxRequests = 10s / 5 = 2s per token. Sleep long enough to refill
	// at least one token so the next request succeeds.
	fmt.Println("\nSleeping 2.5s to allow a token to refill...")
	time.Sleep(2500 * time.Millisecond)
	send("req-9")
}
