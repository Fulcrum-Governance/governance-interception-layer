package codeexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJSAnalyzer_Analyze(t *testing.T) {
	a := &JSAnalyzer{}

	tests := []struct {
		name       string
		code       string
		wantTypes  []string
		wantMinOps int
		wantRisk   string
	}{
		{
			name:       "clean code",
			code:       "const x = 1;\nconsole.log(x);",
			wantMinOps: 0,
			wantRisk:   "read",
		},
		{
			name:      "fetch",
			code:      `const resp = await fetch("https://api.example.com/data");`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "axios",
			code:      `const data = await axios.get("/api/users");`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "http.request",
			code:      `const req = http.request(options, callback);`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "https.request",
			code:      `https.request(url, (res) => {});`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "XMLHttpRequest",
			code:      `const xhr = new XMLHttpRequest();`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "WebSocket",
			code:      `const ws = new WebSocket("ws://localhost:8080");`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "fs.readFile",
			code:      `fs.readFileSync("/etc/passwd", "utf-8");`,
			wantTypes: []string{"file_read"},
			wantRisk:  "read",
		},
		{
			name:      "Deno.readFile",
			code:      `const data = await Deno.readFile("/tmp/config.json");`,
			wantTypes: []string{"file_read"},
			wantRisk:  "read",
		},
		{
			name:      "fs.writeFile",
			code:      `fs.writeFileSync("/tmp/output.txt", "data");`,
			wantTypes: []string{"file_write"},
			wantRisk:  "write",
		},
		{
			name:      "Deno.writeFile",
			code:      `await Deno.writeFile("/tmp/out.txt", encoder.encode("data"));`,
			wantTypes: []string{"file_write"},
			wantRisk:  "write",
		},
		{
			name:      "fs.unlink",
			code:      `fs.unlink("/tmp/file.txt", callback);`,
			wantTypes: []string{"file_delete"},
			wantRisk:  "destructive",
		},
		{
			name:      "fs.rmdir",
			code:      `fs.rmdir("/tmp/dir", { recursive: true }, callback);`,
			wantTypes: []string{"file_delete"},
			wantRisk:  "destructive",
		},
		{
			name:      "fs.rm",
			code:      `await fs.rm("/tmp/dir", { recursive: true });`,
			wantTypes: []string{"file_delete"},
			wantRisk:  "destructive",
		},
		{
			name:      "Deno.remove",
			code:      `await Deno.remove("/tmp/data", { recursive: true });`,
			wantTypes: []string{"file_delete"},
			wantRisk:  "destructive",
		},
		{
			name:      "child_process",
			code:      `const { exec } = require("child_process");`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "spawn",
			code:      `const child = spawn("ls", ["-la"]);`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "Deno.run",
			code:      `const p = Deno.run({ cmd: ["echo", "hello"] });`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "Bun.spawn",
			code:      `const proc = Bun.spawn(["echo", "hello"]);`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "process.env",
			code:      `const key = process.env.API_KEY;`,
			wantTypes: []string{"env_access"},
			wantRisk:  "read",
		},
		{
			name:      "Deno.env",
			code:      `const secret = Deno.env.get("SECRET");`,
			wantTypes: []string{"env_access"},
			wantRisk:  "read",
		},
		{
			name:      "eval",
			code:      `const result = eval("1+1");`,
			wantTypes: []string{"system_call"},
			wantRisk:  "admin",
		},
		{
			name:      "Function constructor",
			code:      `const fn = Function("return 42");`,
			wantTypes: []string{"system_call"},
			wantRisk:  "admin",
		},
		{
			name:      "new Function",
			code:      `const fn = new Function("a", "b", "return a + b");`,
			wantTypes: []string{"system_call"},
			wantRisk:  "admin",
		},
		// --- Obfuscated execution patterns ---
		{
			name:      "obfuscated: eval(atob(...))",
			code:      `eval(atob('Y29uc29sZS5sb2coImhlbGxvIik='));`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: eval(Buffer.from(...))",
			code:      `eval(Buffer.from('Y29uc29sZS5sb2coImhlbGxvIik=', 'base64').toString());`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: new Function(atob(...))",
			code:      `new Function(atob('Y29uc29sZS5sb2coImhlbGxvIik='))();`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: Function(atob(...))",
			code:      `Function(atob('Y29uc29sZS5sb2coImhlbGxvIik='))();`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: child_process with Buffer.from",
			code:      `const { exec } = require('child_process'); exec(Buffer.from('bHMgLWxh', 'base64').toString());`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: exec(atob(...))",
			code:      `exec(atob('bHMgLWxh'));`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:       "benign: btoa/atob without exec sink",
			code:       "const data = btoa('hello');\nconst decoded = atob(data);\nconsole.log(decoded);",
			wantMinOps: 0,
			wantRisk:   "read",
		},
		{
			name: "multiple operations — highest wins",
			code: `const data = fs.readFileSync("/tmp/config.json");
await fs.rm("/tmp/old", { recursive: true });
const resp = await fetch("https://api.example.com");`,
			wantMinOps: 3,
			wantRisk:   "destructive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := a.Analyze(tt.code)

			if tt.wantMinOps > 0 && len(ops) < tt.wantMinOps {
				t.Errorf("ops count = %d, want >= %d", len(ops), tt.wantMinOps)
			}

			for _, wantType := range tt.wantTypes {
				found := false
				for _, op := range ops {
					if op.Type == wantType {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected operation type %q not found in %v", wantType, ops)
				}
			}

			risk := HighestOperationRisk(ops)
			if risk != tt.wantRisk {
				t.Errorf("highest risk = %s, want %s (ops: %v)", risk, tt.wantRisk, ops)
			}
		})
	}
}

func TestJSAnalyzer_ObfuscationFixtures(t *testing.T) {
	a := &JSAnalyzer{}
	fdir := fixturesDir(t)

	tests := []struct {
		fixture        string
		wantObfuscated bool
		wantRisk       string
	}{
		{"obfuscated_eval_atob.js", true, "destructive"},
		{"obfuscated_function_atob.js", true, "destructive"},
		{"obfuscated_child_process.js", true, "destructive"},
		{"benign_base64.js", false, "read"},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			code, err := os.ReadFile(filepath.Join(fdir, tt.fixture))
			if err != nil {
				t.Fatalf("read fixture %s: %v", tt.fixture, err)
			}

			ops := a.Analyze(string(code))

			hasObfuscated := false
			for _, op := range ops {
				if op.Type == "obfuscated_exec" {
					hasObfuscated = true
					break
				}
			}

			if hasObfuscated != tt.wantObfuscated {
				t.Errorf("obfuscated_exec detected = %v, want %v (ops: %v)", hasObfuscated, tt.wantObfuscated, ops)
			}

			risk := HighestOperationRisk(ops)
			if risk != tt.wantRisk {
				t.Errorf("highest risk = %s, want %s (ops: %v)", risk, tt.wantRisk, ops)
			}
		})
	}
}
