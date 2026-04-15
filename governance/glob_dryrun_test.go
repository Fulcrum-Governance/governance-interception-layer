package governance

import (
	"context"
	"strings"
	"testing"
)

func TestToolMatches(t *testing.T) {
	tests := []struct {
		pattern string
		tool    string
		want    bool
	}{
		{"", "anything", true},
		{"*", "anything", true},
		{"rm", "rm", true},
		{"rm", "rmdir", false},
		{"database_*", "database_query", true},
		{"database_*", "database_write", true},
		{"database_*", "database_delete", true},
		{"database_*", "filesystem_read", false},
		{"*.write", "database.write", true},
		{"*.write", "cache.write", true},
		{"*.write", "cache.read", false},
		{"file?", "file1", true},
		{"file?", "file12", false},
		{"[ab]x", "ax", true},
		{"[ab]x", "bx", true},
		{"[ab]x", "cx", false},
		// Malformed pattern: path.Match returns err, we treat as non-match.
		{"[invalid", "invalid", false},
	}
	for _, tt := range tests {
		if got := toolMatches(tt.pattern, tt.tool); got != tt.want {
			t.Errorf("toolMatches(%q, %q) = %v, want %v", tt.pattern, tt.tool, got, tt.want)
		}
	}
}

func TestPipeline_StaticPolicy_GlobDeny(t *testing.T) {
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-db-writes", Tool: "database_*", Action: "deny", Reason: "no direct DB writes"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)

	denyCases := []string{"database_query", "database_write", "database_delete"}
	for _, tool := range denyCases {
		req := &GovernanceRequest{ToolName: tool, Transport: TransportMCP}
		d, err := p.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", tool, err)
		}
		if d.Action != "deny" {
			t.Errorf("expected deny for %s, got %s", tool, d.Action)
		}
	}

	// Non-matching tool should pass through.
	req := &GovernanceRequest{ToolName: "filesystem_read", Transport: TransportMCP}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow for filesystem_read, got %s", d.Action)
	}
}

func TestPipeline_StaticPolicy_ExactMatchRegression(t *testing.T) {
	// Regression: exact matches from before glob support must still work.
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	req := &GovernanceRequest{ToolName: "rm", Transport: TransportCLI}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny, got %s", d.Action)
	}
	// rmdir must NOT match "rm" anymore — exact match only.
	req2 := &GovernanceRequest{ToolName: "rmdir", Transport: TransportCLI}
	d2, err := p.Evaluate(context.Background(), req2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d2.Action != "allow" {
		t.Errorf("expected allow for rmdir under exact-match rule, got %s", d2.Action)
	}
}

func TestPipeline_DryRun_ConvertsDenyToAllow(t *testing.T) {
	auditor := &collectingAuditor{}
	cfg := PipelineConfig{
		DryRun: true,
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive command"},
		},
	}
	p := NewPipeline(cfg, nil, nil, auditor)
	req := &GovernanceRequest{ToolName: "rm", Transport: TransportCLI}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow under dry-run, got %s", d.Action)
	}
	if !d.DryRun {
		t.Error("expected DryRun flag to be set")
	}
	if !strings.HasPrefix(d.Reason, "DRY-RUN would deny:") {
		t.Errorf("expected dry-run reason prefix, got %q", d.Reason)
	}
	if !strings.Contains(d.Reason, "destructive command") {
		t.Errorf("expected original reason preserved, got %q", d.Reason)
	}

	// Audit event must reflect the ORIGINAL deny action.
	events := auditor.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "deny" {
		t.Errorf("expected audit action 'deny' under dry-run, got %q", events[0].Action)
	}
	if events[0].Reason != "destructive command" {
		t.Errorf("expected audit reason 'destructive command', got %q", events[0].Reason)
	}
}

func TestPipeline_DryRun_AllowUnchanged(t *testing.T) {
	cfg := PipelineConfig{DryRun: true}
	p := NewPipeline(cfg, nil, nil, nil)
	req := &GovernanceRequest{ToolName: "read_file", Transport: TransportMCP}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow, got %s", d.Action)
	}
	if d.DryRun {
		t.Error("DryRun flag should be false for naturally-allowed requests")
	}
}

func TestPipeline_DryRunDisabled_DenyReturnsDeny(t *testing.T) {
	// Regression: DryRun defaults to false; denies propagate unchanged.
	cfg := PipelineConfig{
		StaticPolicies: []StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	p := NewPipeline(cfg, nil, nil, nil)
	req := &GovernanceRequest{ToolName: "rm", Transport: TransportCLI}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny with DryRun=false, got %s", d.Action)
	}
	if d.DryRun {
		t.Error("DryRun flag should be false")
	}
}

func TestPipeline_DryRun_EmptyReason(t *testing.T) {
	// Interceptor denies with empty reason → dry-run still converts, prefix applied.
	cfg := PipelineConfig{DryRun: true}
	p := NewPipeline(cfg, nil, nil, nil)
	p.RegisterInterceptor("ambiguous", func(_ context.Context, _ *GovernanceRequest) (*InterceptorResult, error) {
		return &InterceptorResult{Allowed: false, Action: "", Reason: ""}, nil
	})
	req := &GovernanceRequest{ToolName: "ambiguous", Transport: TransportMCP}
	d, err := p.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("expected allow under dry-run, got %s", d.Action)
	}
	if !strings.Contains(d.Reason, "no reason") {
		t.Errorf("expected '(no reason)' placeholder, got %q", d.Reason)
	}
}
