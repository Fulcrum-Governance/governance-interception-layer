package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

func newCapturingLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	// Source=false keeps output predictable.
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), buf
}

func decodeLine(t *testing.T, line []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("decode log line: %v (line=%s)", err, line)
	}
	return m
}

func TestSlogAudit_AllowLogsAtInfo(t *testing.T) {
	logger, buf := newCapturingLogger()
	pub := NewSlogAuditPublisher(logger)

	pub.Publish(context.Background(), AuditEvent{
		RequestID:  "req-1",
		Transport:  TransportMCP,
		ToolName:   "read_file",
		Action:     "allow",
		Reason:     "",
		AgentID:    "agent-A",
		TenantID:   "tenant-1",
		TrustScore: 1.0,
		EnvelopeID: "env-1",
		Timestamp:  time.Unix(1700000000, 0).UTC(),
	})

	rec := decodeLine(t, buf.Bytes())
	if rec["level"] != "INFO" {
		t.Errorf("expected INFO level for allow, got %v", rec["level"])
	}
	if rec["action"] != "allow" {
		t.Errorf("expected action=allow, got %v", rec["action"])
	}
	if rec["msg"] != "governance_decision" {
		t.Errorf("expected msg=governance_decision, got %v", rec["msg"])
	}
	for _, key := range []string{
		"request_id", "transport", "tool_name", "action", "agent_id",
		"tenant_id", "trust_score", "envelope_id", "timestamp",
	} {
		if _, ok := rec[key]; !ok {
			t.Errorf("expected structured attr %q in output", key)
		}
	}
}

func TestSlogAudit_DenyLogsAtWarn(t *testing.T) {
	logger, buf := newCapturingLogger()
	pub := NewSlogAuditPublisher(logger)

	pub.Publish(context.Background(), AuditEvent{
		RequestID: "req-2",
		ToolName:  "rm",
		Action:    "deny",
		Reason:    "destructive",
	})

	rec := decodeLine(t, buf.Bytes())
	if rec["level"] != "WARN" {
		t.Errorf("expected WARN level for deny, got %v", rec["level"])
	}
	if rec["action"] != "deny" {
		t.Errorf("expected action=deny, got %v", rec["action"])
	}
	if rec["reason"] != "destructive" {
		t.Errorf("expected reason=destructive, got %v", rec["reason"])
	}
}

func TestSlogAudit_EscalateAndApprovalLogAtWarn(t *testing.T) {
	for _, action := range []string{"escalate", "require_approval"} {
		logger, buf := newCapturingLogger()
		pub := NewSlogAuditPublisher(logger)
		pub.Publish(context.Background(), AuditEvent{Action: action})
		rec := decodeLine(t, buf.Bytes())
		if rec["level"] != "WARN" {
			t.Errorf("expected WARN for %s, got %v", action, rec["level"])
		}
	}
}

func TestSlogAudit_WarnActionLogsAtInfo(t *testing.T) {
	// "warn" is a governance action that still allows execution; surface at INFO.
	logger, buf := newCapturingLogger()
	pub := NewSlogAuditPublisher(logger)
	pub.Publish(context.Background(), AuditEvent{Action: "warn"})
	rec := decodeLine(t, buf.Bytes())
	if rec["level"] != "INFO" {
		t.Errorf("expected INFO level for governance 'warn' action, got %v", rec["level"])
	}
}

func TestSlogAudit_NilLoggerUsesDefault(t *testing.T) {
	// Passing nil must not panic; slog.Default() takes over.
	pub := NewSlogAuditPublisher(nil)
	// Should not panic. We do not assert on output to avoid coupling to the
	// global default handler configuration.
	pub.Publish(context.Background(), AuditEvent{Action: "allow", ToolName: "t"})
}

func TestSlogAudit_IntegratesWithPipeline(t *testing.T) {
	// End-to-end: pipeline denies a request, the slog publisher is the
	// configured auditor, the log line is WARN with the original reason.
	logger, buf := newCapturingLogger()
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	p := NewPipeline(cfg, nil, nil, NewSlogAuditPublisher(logger))
	_, err := p.Evaluate(context.Background(), &GovernanceRequest{
		ToolName:  "rm",
		Transport: TransportCLI,
		AgentID:   "agent-A",
		TenantID:  "tenant-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec := decodeLine(t, buf.Bytes())
	if rec["level"] != "WARN" {
		t.Errorf("expected WARN from pipeline deny, got %v", rec["level"])
	}
	if rec["action"] != "deny" {
		t.Errorf("expected action=deny, got %v", rec["action"])
	}
	if rec["tool_name"] != "rm" {
		t.Errorf("expected tool_name=rm, got %v", rec["tool_name"])
	}
}
