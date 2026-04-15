package codeexec

import "testing"

func TestDefaultSandboxPolicy(t *testing.T) {
	p := DefaultSandboxPolicy()

	if p.MaxOutputSize != 50*1024 {
		t.Errorf("MaxOutputSize = %d, want %d", p.MaxOutputSize, 50*1024)
	}

	// filesystem_read and env_access should be allowed by default.
	if !p.AllowedCapabilities[CapabilityFilesystemRead] {
		t.Error("expected filesystem_read to be allowed")
	}
	if !p.AllowedCapabilities[CapabilityEnvAccess] {
		t.Error("expected env_access to be allowed")
	}

	// network, filesystem_write, subprocess should be denied.
	if p.AllowedCapabilities[CapabilityNetwork] {
		t.Error("expected network to be denied")
	}
	if p.AllowedCapabilities[CapabilityFilesystemWrite] {
		t.Error("expected filesystem_write to be denied")
	}
	if p.AllowedCapabilities[CapabilitySubprocess] {
		t.Error("expected subprocess to be denied")
	}

	wantLangs := map[string]bool{"python": true, "javascript": true, "typescript": true}
	for _, lang := range p.AllowedLanguages {
		if !wantLangs[lang] {
			t.Errorf("unexpected language %q in default policy", lang)
		}
		delete(wantLangs, lang)
	}
	if len(wantLangs) > 0 {
		t.Errorf("missing languages in default policy: %v", wantLangs)
	}
}

func TestEnforcePolicy(t *testing.T) {
	tests := []struct {
		name        string
		policy      SandboxPolicy
		ops         []Operation
		wantAllowed int
		wantDenied  int
	}{
		{
			name:        "empty ops",
			policy:      DefaultSandboxPolicy(),
			ops:         nil,
			wantAllowed: 0,
			wantDenied:  0,
		},
		{
			name:   "default policy allows file_read and env_access",
			policy: DefaultSandboxPolicy(),
			ops: []Operation{
				{Type: "file_read", Detail: "open()", RiskLevel: "read"},
				{Type: "env_access", Detail: "os.getenv()", RiskLevel: "read"},
			},
			wantAllowed: 2,
			wantDenied:  0,
		},
		{
			name:   "default policy denies network and subprocess",
			policy: DefaultSandboxPolicy(),
			ops: []Operation{
				{Type: "network_call", Detail: "requests.get", RiskLevel: "write"},
				{Type: "subprocess", Detail: "subprocess.run", RiskLevel: "admin"},
			},
			wantAllowed: 0,
			wantDenied:  2,
		},
		{
			name:   "default policy denies file_write and file_delete",
			policy: DefaultSandboxPolicy(),
			ops: []Operation{
				{Type: "file_write", Detail: "shutil.copy", RiskLevel: "write"},
				{Type: "file_delete", Detail: "os.remove", RiskLevel: "destructive"},
			},
			wantAllowed: 0,
			wantDenied:  2,
		},
		{
			name:   "default policy denies system_call and restricted_import",
			policy: DefaultSandboxPolicy(),
			ops: []Operation{
				{Type: "system_call", Detail: "eval()", RiskLevel: "admin"},
				{Type: "restricted_import", Detail: "import ctypes", RiskLevel: "admin"},
			},
			wantAllowed: 0,
			wantDenied:  2,
		},
		{
			name: "permissive policy allows everything",
			policy: SandboxPolicy{
				AllowedCapabilities: map[Capability]bool{
					CapabilityNetwork:         true,
					CapabilityFilesystemRead:  true,
					CapabilityFilesystemWrite: true,
					CapabilitySubprocess:      true,
					CapabilityEnvAccess:       true,
				},
				MaxOutputSize: 100 * 1024,
			},
			ops: []Operation{
				{Type: "network_call", Detail: "fetch", RiskLevel: "write"},
				{Type: "file_read", Detail: "open()", RiskLevel: "read"},
				{Type: "file_delete", Detail: "os.remove", RiskLevel: "destructive"},
				{Type: "subprocess", Detail: "exec()", RiskLevel: "admin"},
				{Type: "env_access", Detail: "process.env", RiskLevel: "read"},
			},
			wantAllowed: 5,
			wantDenied:  0,
		},
		{
			name:   "mixed allow/deny",
			policy: DefaultSandboxPolicy(),
			ops: []Operation{
				{Type: "file_read", Detail: "open()", RiskLevel: "read"},
				{Type: "network_call", Detail: "requests.get", RiskLevel: "write"},
				{Type: "env_access", Detail: "os.environ", RiskLevel: "read"},
				{Type: "subprocess", Detail: "subprocess.run", RiskLevel: "admin"},
			},
			wantAllowed: 2,
			wantDenied:  2,
		},
		{
			name:   "unknown operation type denied by default",
			policy: DefaultSandboxPolicy(),
			ops: []Operation{
				{Type: "quantum_teleport", Detail: "spooky action", RiskLevel: "admin"},
			},
			wantAllowed: 0,
			wantDenied:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, denied := EnforcePolicy(tt.policy, tt.ops)
			if len(allowed) != tt.wantAllowed {
				t.Errorf("allowed count = %d, want %d", len(allowed), tt.wantAllowed)
			}
			if len(denied) != tt.wantDenied {
				t.Errorf("denied count = %d, want %d", len(denied), tt.wantDenied)
			}
		})
	}
}

func TestHighestOperationRisk(t *testing.T) {
	tests := []struct {
		name     string
		ops      []Operation
		wantRisk string
	}{
		{
			name:     "empty ops defaults to read",
			ops:      nil,
			wantRisk: "read",
		},
		{
			name:     "single read",
			ops:      []Operation{{RiskLevel: "read"}},
			wantRisk: "read",
		},
		{
			name:     "single write",
			ops:      []Operation{{RiskLevel: "write"}},
			wantRisk: "write",
		},
		{
			name:     "single admin",
			ops:      []Operation{{RiskLevel: "admin"}},
			wantRisk: "admin",
		},
		{
			name:     "single destructive",
			ops:      []Operation{{RiskLevel: "destructive"}},
			wantRisk: "destructive",
		},
		{
			name: "mixed — destructive wins",
			ops: []Operation{
				{RiskLevel: "read"},
				{RiskLevel: "write"},
				{RiskLevel: "destructive"},
				{RiskLevel: "admin"},
			},
			wantRisk: "destructive",
		},
		{
			name: "mixed — admin wins over write",
			ops: []Operation{
				{RiskLevel: "read"},
				{RiskLevel: "write"},
				{RiskLevel: "admin"},
			},
			wantRisk: "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HighestOperationRisk(tt.ops)
			if got != tt.wantRisk {
				t.Errorf("HighestOperationRisk = %s, want %s", got, tt.wantRisk)
			}
		})
	}
}
