package governance

import (
	"context"
	"log/slog"
)

// SlogAuditPublisher writes governance audit events to a slog.Logger as
// structured records. Allow/warn decisions log at INFO; deny, escalate, and
// require_approval decisions log at WARN. This is the recommended default
// AuditPublisher for development and for production deployments that already
// ship logs to a structured backend.
type SlogAuditPublisher struct {
	Logger *slog.Logger
}

// NewSlogAuditPublisher returns a SlogAuditPublisher that uses the given
// logger. If logger is nil, slog.Default() is used.
func NewSlogAuditPublisher(logger *slog.Logger) *SlogAuditPublisher {
	return &SlogAuditPublisher{Logger: logger}
}

// Publish implements AuditPublisher.
func (p *SlogAuditPublisher) Publish(ctx context.Context, event AuditEvent) {
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}

	level := slog.LevelInfo
	switch event.Action {
	case "deny", "escalate", "require_approval":
		level = slog.LevelWarn
	}

	logger.LogAttrs(ctx, level, "governance_decision",
		slog.String("request_id", event.RequestID),
		slog.String("transport", string(event.Transport)),
		slog.String("tool_name", event.ToolName),
		slog.String("action", event.Action),
		slog.String("reason", event.Reason),
		slog.String("agent_id", event.AgentID),
		slog.String("tenant_id", event.TenantID),
		slog.Float64("trust_score", event.TrustScore),
		slog.String("envelope_id", event.EnvelopeID),
		slog.Time("timestamp", event.Timestamp),
	)
}
