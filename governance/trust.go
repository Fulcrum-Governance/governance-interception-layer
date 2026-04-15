package governance

import "context"

// TrustState represents the circuit breaker state of an agent.
type TrustState int

const (
	TrustStateTrusted    TrustState = 0
	TrustStateEvaluating TrustState = 1
	TrustStateIsolated   TrustState = 2
	TrustStateTerminated TrustState = 3
)

// String returns the human-readable trust state name.
func (s TrustState) String() string {
	switch s {
	case TrustStateTrusted:
		return "TRUSTED"
	case TrustStateEvaluating:
		return "EVALUATING"
	case TrustStateIsolated:
		return "ISOLATED"
	case TrustStateTerminated:
		return "TERMINATED"
	default:
		return "UNKNOWN"
	}
}

// Blocked returns true if the state prevents tool execution.
func (s TrustState) Blocked() bool {
	return s == TrustStateIsolated || s == TrustStateTerminated
}

// TrustChecker looks up the trust/circuit-breaker state for an agent.
// The concrete implementation lives in internal/trust (Redis-backed).
type TrustChecker interface {
	CheckAgentState(ctx context.Context, agentID string) (TrustState, error)
}
