package governance

import "testing"

func TestHighestRisk(t *testing.T) {
	tests := []struct {
		name     string
		segments []PipeSegment
		want     string
	}{
		{"empty", nil, "read"},
		{"single read", []PipeSegment{{RiskLevel: "read"}}, "read"},
		{"single write", []PipeSegment{{RiskLevel: "write"}}, "write"},
		{"mixed read+write", []PipeSegment{{RiskLevel: "read"}, {RiskLevel: "write"}}, "write"},
		{"mixed all levels", []PipeSegment{
			{RiskLevel: "read"},
			{RiskLevel: "admin"},
			{RiskLevel: "write"},
		}, "admin"},
		{"destructive wins", []PipeSegment{
			{RiskLevel: "read"},
			{RiskLevel: "destructive"},
			{RiskLevel: "admin"},
		}, "destructive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HighestRisk(tt.segments)
			if got != tt.want {
				t.Errorf("HighestRisk() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGovernanceDecision_Allowed(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{"allow", true},
		{"warn", true},
		{"deny", false},
		{"escalate", false},
		{"require_approval", false},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			d := &GovernanceDecision{Action: tt.action}
			if got := d.Allowed(); got != tt.want {
				t.Errorf("Allowed() for action %q = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestTrustState_Blocked(t *testing.T) {
	tests := []struct {
		state TrustState
		want  bool
	}{
		{TrustStateTrusted, false},
		{TrustStateEvaluating, false},
		{TrustStateIsolated, true},
		{TrustStateTerminated, true},
	}
	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			if got := tt.state.Blocked(); got != tt.want {
				t.Errorf("Blocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrustState_String(t *testing.T) {
	tests := []struct {
		state TrustState
		want  string
	}{
		{TrustStateTrusted, "TRUSTED"},
		{TrustStateEvaluating, "EVALUATING"},
		{TrustStateIsolated, "ISOLATED"},
		{TrustStateTerminated, "TERMINATED"},
		{TrustState(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
