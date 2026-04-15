package codeexec

import "regexp"

// JSAnalyzer detects risky operations in JavaScript and TypeScript source
// code using regexp-based pattern matching (not AST parsing).
type JSAnalyzer struct{}

// jsPattern groups a compiled regex with the operation metadata emitted
// when the pattern matches.
type jsPattern struct {
	re        *regexp.Regexp
	opType    string
	riskLevel string
	detail    string
}

// jsPatterns is the static set of patterns checked against every input.
var jsPatterns = []jsPattern{
	// --- Network calls (write) ---
	{regexp.MustCompile(`\bfetch\s*\(`), "network_call", "write", "fetch() call"},
	{regexp.MustCompile(`axios\.`), "network_call", "write", "axios usage"},
	{regexp.MustCompile(`\bhttp\.request\b`), "network_call", "write", "http.request call"},
	{regexp.MustCompile(`\bhttps\.request\b`), "network_call", "write", "https.request call"},
	{regexp.MustCompile(`XMLHttpRequest`), "network_call", "write", "XMLHttpRequest usage"},
	{regexp.MustCompile(`new\s+WebSocket`), "network_call", "write", "WebSocket creation"},

	// --- File read (read) ---
	{regexp.MustCompile(`fs\.readFile`), "file_read", "read", "fs.readFile call"},
	{regexp.MustCompile(`Deno\.readFile`), "file_read", "read", "Deno.readFile call"},

	// --- File write (write) ---
	{regexp.MustCompile(`fs\.writeFile`), "file_write", "write", "fs.writeFile call"},
	{regexp.MustCompile(`Deno\.writeFile`), "file_write", "write", "Deno.writeFile call"},

	// --- File delete (destructive) ---
	{regexp.MustCompile(`fs\.unlink\b`), "file_delete", "destructive", "fs.unlink call"},
	{regexp.MustCompile(`fs\.rmdir\b`), "file_delete", "destructive", "fs.rmdir call"},
	{regexp.MustCompile(`fs\.rm\b`), "file_delete", "destructive", "fs.rm call"},
	{regexp.MustCompile(`Deno\.remove`), "file_delete", "destructive", "Deno.remove call"},

	// --- Subprocess (admin) ---
	{regexp.MustCompile(`child_process`), "subprocess", "admin", "child_process usage"},
	{regexp.MustCompile(`\bexec\s*\(`), "subprocess", "admin", "exec() call"},
	{regexp.MustCompile(`\bspawn\s*\(`), "subprocess", "admin", "spawn() call"},
	{regexp.MustCompile(`Deno\.run`), "subprocess", "admin", "Deno.run call"},
	{regexp.MustCompile(`Bun\.spawn`), "subprocess", "admin", "Bun.spawn call"},

	// --- Env access (read) ---
	{regexp.MustCompile(`process\.env`), "env_access", "read", "process.env access"},
	{regexp.MustCompile(`Deno\.env`), "env_access", "read", "Deno.env access"},

	// --- Dangerous patterns (admin) ---
	{regexp.MustCompile(`\beval\s*\(`), "system_call", "admin", "eval() call"},
	{regexp.MustCompile(`\bFunction\s*\(`), "system_call", "admin", "Function() constructor"},
	{regexp.MustCompile(`new\s+Function`), "system_call", "admin", "new Function() constructor"},

	// --- Obfuscated execution patterns (destructive) ---
	// eval(atob(...)) — base64 decode + eval
	{regexp.MustCompile(`\beval\s*\(\s*atob\s*\(`), "obfuscated_exec", "destructive", "eval(atob(...)) obfuscated execution"},
	{regexp.MustCompile(`\beval\s*\(\s*Buffer\.from\s*\(`), "obfuscated_exec", "destructive", "eval(Buffer.from(...)) obfuscated execution"},
	// new Function(atob(...)) — base64 decode + Function constructor
	{regexp.MustCompile(`new\s+Function\s*\(\s*atob\s*\(`), "obfuscated_exec", "destructive", "new Function(atob(...)) obfuscated execution"},
	{regexp.MustCompile(`\bFunction\s*\(\s*atob\s*\(`), "obfuscated_exec", "destructive", "Function(atob(...)) obfuscated execution"},
	{regexp.MustCompile(`new\s+Function\s*\(\s*Buffer\.from\s*\(`), "obfuscated_exec", "destructive", "new Function(Buffer.from(...)) obfuscated execution"},
	// child_process with encoded args
	{regexp.MustCompile(`child_process.*Buffer\.from\s*\(`), "obfuscated_exec", "destructive", "child_process with Buffer.from(...) encoded execution"},
	{regexp.MustCompile(`child_process.*atob\s*\(`), "obfuscated_exec", "destructive", "child_process with atob(...) encoded execution"},
	// exec/spawn with decoded payload
	{regexp.MustCompile(`\bexec\s*\(\s*atob\s*\(`), "obfuscated_exec", "destructive", "exec(atob(...)) obfuscated execution"},
	{regexp.MustCompile(`\bexec\s*\(\s*Buffer\.from\s*\(`), "obfuscated_exec", "destructive", "exec(Buffer.from(...)) obfuscated execution"},

	// --- Trusted library eval delegation ---
	{regexp.MustCompile(`vm\.runInNewContext\s*\(`), "eval_delegation", "destructive", "Node.js vm.runInNewContext() executes arbitrary code"},
	{regexp.MustCompile(`vm\.createScript\s*\(`), "eval_delegation", "destructive", "Node.js vm.createScript() code execution"},
	{regexp.MustCompile(`vm\.compileFunction\s*\(`), "eval_delegation", "destructive", "Node.js vm.compileFunction() code execution"},
}

// Analyze scans JavaScript/TypeScript source code for risky operations.
func (a *JSAnalyzer) Analyze(code string) []Operation {
	var ops []Operation
	for _, p := range jsPatterns {
		if p.re.MatchString(code) {
			ops = append(ops, Operation{
				Type:      p.opType,
				Detail:    p.detail,
				RiskLevel: p.riskLevel,
			})
		}
	}
	return ops
}
