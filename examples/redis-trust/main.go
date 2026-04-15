// Example: Redis-backed TrustChecker implementation.
//
// The GIL pipeline's Stage 1 is a trust / circuit-breaker check. Any type
// that satisfies governance.TrustChecker can be plugged in. This example
// implements one against Redis using github.com/redis/go-redis/v9.
//
// In production, Fulcrum uses this pattern with persistent Redis-backed trust
// state and Beta distribution scoring. See fulcrum-trust on PyPI for the
// trust evaluation library.
//
// Run with a local Redis:
//
//	redis-cli SET trust:agent-quarantine ISOLATED
//	go run main.go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/fulcrum-governance/gil/governance"
)

// RedisTrustChecker reads agent trust state from Redis keys of the form
// "trust:<agentID>". Absent keys fall back to TRUSTED (fail-open read).
type RedisTrustChecker struct {
	client *redis.Client
}

func NewRedisTrustChecker(client *redis.Client) *RedisTrustChecker {
	return &RedisTrustChecker{client: client}
}

// CheckAgentState satisfies governance.TrustChecker.
func (r *RedisTrustChecker) CheckAgentState(ctx context.Context, agentID string) (governance.TrustState, error) {
	val, err := r.client.Get(ctx, "trust:"+agentID).Result()
	if err == redis.Nil {
		return governance.TrustStateTrusted, nil
	}
	if err != nil {
		return governance.TrustStateIsolated, fmt.Errorf("redis lookup: %w", err)
	}
	switch val {
	case "TRUSTED":
		return governance.TrustStateTrusted, nil
	case "EVALUATING":
		return governance.TrustStateEvaluating, nil
	case "ISOLATED":
		return governance.TrustStateIsolated, nil
	case "TERMINATED":
		return governance.TrustStateTerminated, nil
	default:
		return governance.TrustStateEvaluating, nil
	}
}

func main() {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer client.Close()

	// Seed an ISOLATED agent for the demo. In production this state is
	// written by the trust evaluation subsystem, not by the proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Set(ctx, "trust:agent-quarantine", "ISOLATED", time.Minute).Err(); err != nil {
		fmt.Printf("redis seed failed (is Redis running on :6379?): %v\n", err)
		return
	}

	pipeline := governance.NewPipeline(governance.PipelineConfig{}, NewRedisTrustChecker(client), nil, nil)

	req := &governance.GovernanceRequest{
		ToolName:  "read_file",
		Transport: governance.TransportMCP,
		AgentID:   "agent-quarantine",
		TenantID:  "tenant-1",
	}
	decision, err := pipeline.Evaluate(ctx, req)
	if err != nil {
		fmt.Printf("evaluate: %v\n", err)
		return
	}
	fmt.Printf("agent=%s action=%s reason=%s trust_score=%.2f\n",
		req.AgentID, decision.Action, decision.Reason, decision.TrustScore)
}
