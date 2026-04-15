package governance

import (
	"context"
	"testing"
)

// TestParity_SamePolicyAcrossTransports verifies that the same governance
// pipeline configuration produces identical decisions regardless of transport.
func TestParity_SamePolicyAcrossTransports(t *testing.T) {
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive command"},
			{Name: "block-exec-os-remove", Tool: "os.remove", Action: "deny", Reason: "destructive code"},
		},
	}
	pipe := NewPipeline(cfg, nil, nil, nil)

	tests := []struct {
		name       string
		req        *GovernanceRequest
		wantAllow  bool
		wantAction string
	}{
		{
			name: "MCP/allow/read_file",
			req: &GovernanceRequest{
				Transport: TransportMCP,
				ToolName:  "read_file",
				AgentID:   "agent-1",
			},
			wantAllow:  true,
			wantAction: "allow",
		},
		{
			name: "CLI/allow/read_file",
			req: &GovernanceRequest{
				Transport: TransportCLI,
				ToolName:  "cat",
				AgentID:   "agent-1",
				Command:   "cat /etc/hosts",
			},
			wantAllow:  true,
			wantAction: "allow",
		},
		{
			name: "CodeExec/allow/read_file",
			req: &GovernanceRequest{
				Transport: TransportCodeExec,
				ToolName:  "code_exec",
				AgentID:   "agent-1",
				Code:      "open('/etc/hosts').read()",
				Language:  "python",
			},
			wantAllow:  true,
			wantAction: "allow",
		},
		{
			name: "MCP/deny/rm",
			req: &GovernanceRequest{
				Transport: TransportMCP,
				ToolName:  "rm",
				AgentID:   "agent-1",
			},
			wantAllow:  false,
			wantAction: "deny",
		},
		{
			name: "CLI/deny/rm",
			req: &GovernanceRequest{
				Transport: TransportCLI,
				ToolName:  "rm",
				AgentID:   "agent-1",
				Command:   "rm -rf /tmp/data",
			},
			wantAllow:  false,
			wantAction: "deny",
		},
		{
			name: "CodeExec/deny/os.remove",
			req: &GovernanceRequest{
				Transport: TransportCodeExec,
				ToolName:  "os.remove",
				AgentID:   "agent-1",
				Code:      "os.remove('/tmp/data')",
				Language:  "python",
			},
			wantAllow:  false,
			wantAction: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := pipe.Evaluate(context.Background(), tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Allowed() != tt.wantAllow {
				t.Errorf("Allowed() = %v, want %v (action=%s)", decision.Allowed(), tt.wantAllow, decision.Action)
			}
			if decision.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", decision.Action, tt.wantAction)
			}
		})
	}
}

// TestParity_TrustDenyAcrossTransports verifies that trust-based denial
// is consistent across all transports.
func TestParity_TrustDenyAcrossTransports(t *testing.T) {
	tc := &mockTrustChecker{
		states: map[string]TrustState{"bad-agent": TrustStateIsolated},
	}
	pipe := NewPipeline(PipelineConfig{}, tc, nil, nil)

	transports := []TransportType{TransportMCP, TransportCLI, TransportCodeExec}

	for _, transport := range transports {
		t.Run(string(transport), func(t *testing.T) {
			req := &GovernanceRequest{
				Transport: transport,
				ToolName:  "any_tool",
				AgentID:   "bad-agent",
			}
			decision, err := pipe.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Action != "deny" {
				t.Errorf("expected deny for %s, got %s", transport, decision.Action)
			}
			if decision.TrustScore != 0.0 {
				t.Errorf("expected trust score 0.0 for %s, got %f", transport, decision.TrustScore)
			}
		})
	}
}

// TestParity_AuditEventsAcrossTransports verifies that audit events
// contain the correct transport field for each adapter.
func TestParity_AuditEventsAcrossTransports(t *testing.T) {
	auditor := &collectingAuditor{}
	pipe := NewPipeline(PipelineConfig{}, nil, nil, auditor)

	transports := []TransportType{TransportMCP, TransportCLI, TransportCodeExec}

	for _, transport := range transports {
		req := &GovernanceRequest{
			Transport: transport,
			ToolName:  "any_tool",
			TenantID:  "tenant-1",
		}
		_, err := pipe.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", transport, err)
		}
	}

	events := auditor.Events()
	if len(events) != 3 {
		t.Fatalf("expected 3 audit events, got %d", len(events))
	}

	for i, transport := range transports {
		if events[i].Transport != transport {
			t.Errorf("event[%d] transport = %s, want %s", i, events[i].Transport, transport)
		}
	}
}

// TestParity_InterceptorAcrossTransports verifies that a domain interceptor
// registered for a tool name works identically across transports.
func TestParity_InterceptorAcrossTransports(t *testing.T) {
	pipe := NewPipeline(PipelineConfig{}, nil, nil, nil)
	pipe.RegisterInterceptor("restricted_tool", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return &InterceptorResult{Allowed: false, Action: "deny", Reason: "interceptor: restricted"}, nil
	})

	transports := []TransportType{TransportMCP, TransportCLI, TransportCodeExec}

	for _, transport := range transports {
		t.Run(string(transport), func(t *testing.T) {
			req := &GovernanceRequest{
				Transport: transport,
				ToolName:  "restricted_tool",
			}
			decision, err := pipe.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Action != "deny" {
				t.Errorf("expected deny for %s, got %s", transport, decision.Action)
			}
			if decision.Reason != "interceptor: restricted" {
				t.Errorf("expected interceptor reason for %s, got %q", transport, decision.Reason)
			}
		})
	}
}
