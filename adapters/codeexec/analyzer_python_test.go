package codeexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPythonAnalyzer_Analyze(t *testing.T) {
	a := &PythonAnalyzer{}

	tests := []struct {
		name       string
		code       string
		wantTypes  []string // expected operation types (subset)
		wantMinOps int
		wantRisk   string // expected highest risk
	}{
		{
			name:       "clean code",
			code:       "x = 1\ny = x + 2\nprint(y)",
			wantMinOps: 0,
			wantRisk:   "read",
		},
		{
			name:      "requests.get",
			code:      `response = requests.get("https://api.example.com/data")`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "requests.post",
			code:      `requests.post("https://api.example.com", json=data)`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "urllib",
			code:      `import urllib.request\nurllib.request.urlopen("https://example.com")`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "httpx",
			code:      `client = httpx.Client()\nclient.get("https://example.com")`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "aiohttp",
			code:      `async with aiohttp.ClientSession() as session:`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "socket.connect",
			code:      `s = socket.socket()\ns.connect(("localhost", 8080))`,
			wantTypes: []string{"network_call"},
			wantRisk:  "write",
		},
		{
			name:      "open file",
			code:      `f = open("/etc/passwd", "r")`,
			wantTypes: []string{"file_read"},
			wantRisk:  "read",
		},
		{
			name:      "pathlib",
			code:      `p = pathlib.Path("/tmp/data")`,
			wantTypes: []string{"file_read"},
			wantRisk:  "read",
		},
		{
			name:      "shutil.copy",
			code:      `shutil.copy("a.txt", "b.txt")`,
			wantTypes: []string{"file_write"},
			wantRisk:  "write",
		},
		{
			name:      "shutil.move",
			code:      `shutil.move("/tmp/a", "/tmp/b")`,
			wantTypes: []string{"file_write"},
			wantRisk:  "write",
		},
		{
			name:      "os.remove",
			code:      `os.remove("/tmp/secret.txt")`,
			wantTypes: []string{"file_delete"},
			wantRisk:  "destructive",
		},
		{
			name:      "os.unlink",
			code:      `os.unlink("/tmp/link")`,
			wantTypes: []string{"file_delete"},
			wantRisk:  "destructive",
		},
		{
			name:      "os.rmdir",
			code:      `os.rmdir("/tmp/empty")`,
			wantTypes: []string{"file_delete"},
			wantRisk:  "destructive",
		},
		{
			name:      "shutil.rmtree",
			code:      `shutil.rmtree("/var/data")`,
			wantTypes: []string{"file_delete"},
			wantRisk:  "destructive",
		},
		{
			name:      "subprocess.run",
			code:      `subprocess.run(["ls", "-la"])`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "subprocess.Popen",
			code:      `p = subprocess.Popen(["cat", "/etc/hosts"], stdout=subprocess.PIPE)`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "os.system",
			code:      `os.system("rm -rf /tmp/*")`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "os.popen",
			code:      `os.popen("whoami")`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "os.exec",
			code:      `os.execvp("python3", ["python3", "script.py"])`,
			wantTypes: []string{"subprocess"},
			wantRisk:  "admin",
		},
		{
			name:      "import ctypes",
			code:      `import ctypes`,
			wantTypes: []string{"restricted_import"},
			wantRisk:  "admin",
		},
		{
			name:      "import importlib",
			code:      `import importlib`,
			wantTypes: []string{"restricted_import"},
			wantRisk:  "admin",
		},
		{
			name:      "import __builtins__",
			code:      `import __builtins__`,
			wantTypes: []string{"restricted_import"},
			wantRisk:  "admin",
		},
		{
			name:      "os.environ",
			code:      `key = os.environ["API_KEY"]`,
			wantTypes: []string{"env_access"},
			wantRisk:  "read",
		},
		{
			name:      "os.getenv",
			code:      `secret = os.getenv("SECRET")`,
			wantTypes: []string{"env_access"},
			wantRisk:  "read",
		},
		{
			name:      "eval",
			code:      `result = eval("1+1")`,
			wantTypes: []string{"system_call"},
			wantRisk:  "admin",
		},
		{
			name:      "exec",
			code:      `exec("print('hello')")`,
			wantTypes: []string{"system_call"},
			wantRisk:  "admin",
		},
		{
			name:      "compile",
			code:      `code = compile("x=1", "<string>", "exec")`,
			wantTypes: []string{"system_call"},
			wantRisk:  "admin",
		},
		{
			name:      "__import__",
			code:      `mod = __import__("os")`,
			wantTypes: []string{"system_call"},
			wantRisk:  "admin",
		},
		// --- Obfuscated execution patterns ---
		{
			name:      "obfuscated: exec(base64.b64decode(...))",
			code:      `exec(base64.b64decode(b'cHJpbnQoImhlbGxvIik=').decode())`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: eval(base64.b64decode(...))",
			code:      `eval(base64.b64decode(b'MSsx').decode())`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: eval(compile(...))",
			code:      `eval(compile("print('hello')", "<string>", "exec"))`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: __import__('builtins').exec(...)",
			code:      `__import__('builtins').exec('print("hello")')`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: subprocess.run with b64 args",
			code:      `subprocess.run([base64.b64decode(b'bHM=').decode(), '-la'])`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: pickle.loads(base64.b64decode(...))",
			code:      `pickle.loads(base64.b64decode(b'gASVFAAAAA=='))`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: os.system(base64.b64decode(...).decode())",
			code:      `os.system(base64.b64decode(b'bHM=').decode())`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: exec(codecs.decode(...))",
			code:      `exec(codecs.decode(b'...', 'rot_13'))`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: exec(bytes.fromhex(...))",
			code:      `exec(bytes.fromhex('7072696e7428312b3129').decode())`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:      "obfuscated: exec(zlib.decompress(...)) nested",
			code:      `exec(zlib.decompress(base64.b64decode(b'eJwrzs9NyclRKM8vyklRBAAPngQ3')))`,
			wantTypes: []string{"obfuscated_exec"},
			wantRisk:  "destructive",
		},
		{
			name:       "benign: base64.b64encode (no exec sink)",
			code:       "import base64\ndata = base64.b64encode(b'hello')\nprint(data)",
			wantMinOps: 0,
			wantRisk:   "read",
		},
		{
			name: "multiple operations — highest wins",
			code: `import os
f = open("/tmp/data.txt")
os.remove("/tmp/data.txt")
subprocess.run(["ls"])`,
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

			// Verify expected operation types are present.
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

			// Verify highest risk level.
			risk := HighestOperationRisk(ops)
			if risk != tt.wantRisk {
				t.Errorf("highest risk = %s, want %s (ops: %v)", risk, tt.wantRisk, ops)
			}
		})
	}
}

// fixturesDir returns the absolute path to the test fixtures directory.
// It walks up from the test file to find the repo root via go.mod.
func fixturesDir(t *testing.T) string {
	t.Helper()
	// Start from the current working directory and walk up to find go.mod.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "tests", "adapters", "codeexec", "fixtures")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}

func TestPythonAnalyzer_ObfuscationFixtures(t *testing.T) {
	a := &PythonAnalyzer{}
	fdir := fixturesDir(t)

	tests := []struct {
		fixture        string
		wantObfuscated bool // should contain obfuscated_exec operation
		wantRisk       string
	}{
		{"obfuscated_base64_exec.py", true, "destructive"},
		{"obfuscated_dynamic_import.py", true, "destructive"},
		{"obfuscated_pickle.py", true, "destructive"},
		{"obfuscated_subprocess.py", true, "destructive"},
		{"obfuscated_nested.py", true, "destructive"},
		{"benign_base64.py", false, "read"},
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
