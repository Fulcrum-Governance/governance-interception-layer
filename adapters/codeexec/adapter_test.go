package codeexec

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fulcrum-governance/gil/governance"
)

// Compile-time interface check.
var _ governance.TransportAdapter = (*Adapter)(nil)

func TestAdapter_Type(t *testing.T) {
	a := NewAdapter("tenant-1")
	if a.Type() != governance.TransportCodeExec {
		t.Errorf("expected TransportCodeExec, got %s", a.Type())
	}
}

func TestAdapter_ParseRequest(t *testing.T) {
	tests := []struct {
		name       string
		raw        any
		wantErr    bool
		errContain string
		checkReq   func(t *testing.T, req *governance.GovernanceRequest)
	}{
		{
			name: "struct pointer",
			raw: &CodeExecInput{
				Code:      "print('hello')",
				Language:  "python",
				SandboxID: "sb-1",
				AgentID:   "agent-1",
				TenantID:  "tenant-1",
			},
			checkReq: func(t *testing.T, req *governance.GovernanceRequest) {
				t.Helper()
				if req.Transport != governance.TransportCodeExec {
					t.Errorf("transport = %s, want TransportCodeExec", req.Transport)
				}
				if req.ToolName != "code_exec" {
					t.Errorf("tool_name = %s, want code_exec", req.ToolName)
				}
				if req.Code != "print('hello')" {
					t.Errorf("code = %s, want print('hello')", req.Code)
				}
				if req.Language != "python" {
					t.Errorf("language = %s, want python", req.Language)
				}
				if req.SandboxID != "sb-1" {
					t.Errorf("sandbox_id = %s, want sb-1", req.SandboxID)
				}
				if req.AgentID != "agent-1" {
					t.Errorf("agent_id = %s, want agent-1", req.AgentID)
				}
				if req.TenantID != "tenant-1" {
					t.Errorf("tenant_id = %s, want tenant-1", req.TenantID)
				}
				if req.RequestID == "" {
					t.Error("expected request ID to be generated")
				}
				// print() is harmless — action should be "read"
				if req.Action != "read" {
					t.Errorf("action = %s, want read", req.Action)
				}
			},
		},
		{
			name: "struct value",
			raw: CodeExecInput{
				Code:     "x = 1",
				Language: "python",
			},
			checkReq: func(t *testing.T, req *governance.GovernanceRequest) {
				t.Helper()
				if req.Code != "x = 1" {
					t.Errorf("code = %s, want x = 1", req.Code)
				}
			},
		},
		{
			name: "json.RawMessage",
			raw:  json.RawMessage(`{"code":"import os\nos.system('ls')","language":"python","agent_id":"a1"}`),
			checkReq: func(t *testing.T, req *governance.GovernanceRequest) {
				t.Helper()
				if req.AgentID != "a1" {
					t.Errorf("agent_id = %s, want a1", req.AgentID)
				}
				// os.system triggers admin risk
				if req.Action != "admin" {
					t.Errorf("action = %s, want admin", req.Action)
				}
			},
		},
		{
			name: "[]byte",
			raw:  []byte(`{"code":"console.log('hi')","language":"javascript"}`),
			checkReq: func(t *testing.T, req *governance.GovernanceRequest) {
				t.Helper()
				if req.Language != "javascript" {
					t.Errorf("language = %s, want javascript", req.Language)
				}
			},
		},
		{
			name: "default tenant ID used when omitted",
			raw: &CodeExecInput{
				Code:     "1+1",
				Language: "python",
			},
			checkReq: func(t *testing.T, req *governance.GovernanceRequest) {
				t.Helper()
				if req.TenantID != "default-tenant" {
					t.Errorf("tenant_id = %s, want default-tenant", req.TenantID)
				}
			},
		},
		{
			name: "destructive code detected",
			raw: &CodeExecInput{
				Code:     "import shutil\nshutil.rmtree('/tmp/data')",
				Language: "python",
			},
			checkReq: func(t *testing.T, req *governance.GovernanceRequest) {
				t.Helper()
				if req.Action != "destructive" {
					t.Errorf("action = %s, want destructive", req.Action)
				}
			},
		},
		{
			name: "unsupported language still parses",
			raw: &CodeExecInput{
				Code:     "echo hello",
				Language: "bash",
			},
			checkReq: func(t *testing.T, req *governance.GovernanceRequest) {
				t.Helper()
				// No analyser for bash — defaults to "read"
				if req.Action != "read" {
					t.Errorf("action = %s, want read", req.Action)
				}
				if req.Language != "bash" {
					t.Errorf("language = %s, want bash", req.Language)
				}
			},
		},
		{
			name:       "unsupported raw type",
			raw:        42,
			wantErr:    true,
			errContain: "unsupported raw type",
		},
		{
			name:       "invalid JSON",
			raw:        json.RawMessage(`{bad json}`),
			wantErr:    true,
			errContain: "unmarshal",
		},
		{
			name:       "empty code",
			raw:        &CodeExecInput{Language: "python"},
			wantErr:    true,
			errContain: "code field is required",
		},
		{
			name:       "empty language",
			raw:        &CodeExecInput{Code: "x = 1"},
			wantErr:    true,
			errContain: "language field is required",
		},
	}

	a := NewAdapter("default-tenant")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := a.ParseRequest(context.Background(), tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("error %q does not contain %q", err, tt.errContain)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkReq != nil {
				tt.checkReq(t, req)
			}
		})
	}
}

func TestAdapter_InspectResponse(t *testing.T) {
	a := NewAdapter("default-tenant")

	tests := []struct {
		name          string
		resp          *governance.ToolResponse
		wantSafe      bool
		wantSensitive bool
		wantConcerns  int // minimum number of concerns
	}{
		{
			name:     "nil response",
			resp:     nil,
			wantSafe: true,
		},
		{
			name:     "small safe output",
			resp:     &governance.ToolResponse{Content: []byte("hello world")},
			wantSafe: true,
		},
		{
			name: "oversized output",
			resp: &governance.ToolResponse{
				Content: make([]byte, 60*1024), // 60 KB
			},
			wantSafe:     false,
			wantConcerns: 1,
		},
		{
			name: "sensitive data — private key",
			resp: &governance.ToolResponse{
				Content: []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."),
			},
			wantSafe:      false,
			wantSensitive: true,
			wantConcerns:  1,
		},
		{
			name: "sensitive data — AWS key",
			resp: &governance.ToolResponse{
				Content: []byte("export AWS_ACCESS_KEY_ID=AKIA" + "PLACEHOLDER_TEST"),
			},
			wantSafe:      false,
			wantSensitive: true,
			wantConcerns:  1,
		},
		{
			name: "non-zero exit code",
			resp: &governance.ToolResponse{
				Content:  []byte("permission denied"),
				ExitCode: 1,
			},
			wantSafe:     true, // exit code alone doesn't make it unsafe
			wantConcerns: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insp, err := a.InspectResponse(context.Background(), tt.resp)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if insp.Safe != tt.wantSafe {
				t.Errorf("safe = %v, want %v", insp.Safe, tt.wantSafe)
			}
			if insp.SensitiveData != tt.wantSensitive {
				t.Errorf("sensitive_data = %v, want %v", insp.SensitiveData, tt.wantSensitive)
			}
			if len(insp.Concerns) < tt.wantConcerns {
				t.Errorf("concerns count = %d, want >= %d", len(insp.Concerns), tt.wantConcerns)
			}
		})
	}
}

func TestAdapter_EmitGovernanceMetadata(t *testing.T) {
	a := NewAdapter("default-tenant")

	tests := []struct {
		name     string
		resp     *governance.ToolResponse
		decision *governance.GovernanceDecision
		wantKeys []string
	}{
		{
			name:     "nil inputs",
			resp:     nil,
			decision: nil,
		},
		{
			name: "populates metadata",
			resp: &governance.ToolResponse{Content: []byte("ok")},
			decision: &governance.GovernanceDecision{
				Action:     "allow",
				EnvelopeID: "env-1",
				RequestID:  "req-1",
			},
			wantKeys: []string{
				"x-fulcrum-action",
				"x-fulcrum-envelope-id",
				"x-fulcrum-request-id",
				"x-fulcrum-transport",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := a.EmitGovernanceMetadata(context.Background(), tt.resp, tt.decision)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.resp != nil && tt.wantKeys != nil {
				for _, key := range tt.wantKeys {
					if _, ok := tt.resp.Metadata[key]; !ok {
						t.Errorf("missing metadata key %q", key)
					}
				}
				if tt.resp.Metadata["x-fulcrum-transport"] != "code_exec" {
					t.Errorf("transport = %s, want code_exec", tt.resp.Metadata["x-fulcrum-transport"])
				}
			}
		})
	}
}

func TestAdapter_ForwardGoverned_Stub(t *testing.T) {
	a := NewAdapter("default-tenant")
	_, err := a.ForwardGoverned(context.Background(), nil, nil)
	if err == nil {
		t.Error("expected error from stub ForwardGoverned")
	}
}
