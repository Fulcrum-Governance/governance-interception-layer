package governance

import (
	"context"
	"time"
)

// AuditEvent represents a governance audit record emitted after every
// pipeline evaluation, regardless of outcome.
type AuditEvent struct {
	RequestID  string                 `json:"request_id"`
	Transport  TransportType          `json:"transport"`
	ToolName   string                 `json:"tool_name"`
	Action     string                 `json:"action"`
	Reason     string                 `json:"reason,omitempty"`
	TrustScore float64                `json:"trust_score"`
	EnvelopeID string                 `json:"envelope_id"`
	AgentID    string                 `json:"agent_id,omitempty"`
	TenantID   string                 `json:"tenant_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	// DecisionMode mirrors GovernanceDecision.DecisionMode so audit sinks
	// can filter or aggregate by epistemic confidence level.
	DecisionMode DecisionMode `json:"decision_mode,omitempty"`
}

// AuditPublisher publishes governance audit events.
// The concrete implementation uses NATS JetStream (internal/securemcp/audit.go).
type AuditPublisher interface {
	Publish(ctx context.Context, event AuditEvent)
}

// noopAuditPublisher silently discards events.
type noopAuditPublisher struct{}

func (noopAuditPublisher) Publish(context.Context, AuditEvent) {}
