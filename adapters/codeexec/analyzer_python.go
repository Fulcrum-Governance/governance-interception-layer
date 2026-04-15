package codeexec

import "regexp"

// PythonAnalyzer detects risky operations in Python source code using
// regexp-based pattern matching (not AST parsing).
type PythonAnalyzer struct{}

// pythonPattern groups a compiled regex with the operation metadata emitted
// when the pattern matches.
type pythonPattern struct {
	re        *regexp.Regexp
	opType    string
	riskLevel string
	detail    string
}

// pythonPatterns is the static set of patterns checked against every input.
var pythonPatterns = []pythonPattern{
	// --- Network calls (write) ---
	{regexp.MustCompile(`requests\.(get|post|put|patch|delete|head|options)\s*\(`), "network_call", "write", "requests HTTP call"},
	{regexp.MustCompile(`urllib\.request`), "network_call", "write", "urllib.request usage"},
	{regexp.MustCompile(`httpx\.`), "network_call", "write", "httpx usage"},
	{regexp.MustCompile(`aiohttp\.`), "network_call", "write", "aiohttp usage"},
	{regexp.MustCompile(`socket\.connect`), "network_call", "write", "socket.connect call"},
	{regexp.MustCompile(`socket\.socket`), "network_call", "write", "socket.socket creation"},

	// --- File read (read) ---
	{regexp.MustCompile(`\bopen\s*\(`), "file_read", "read", "open() call"},
	{regexp.MustCompile(`pathlib\.Path\s*\(`), "file_read", "read", "pathlib.Path usage"},

	// --- File write (write) ---
	{regexp.MustCompile(`shutil\.copy`), "file_write", "write", "shutil.copy"},
	{regexp.MustCompile(`shutil\.move`), "file_write", "write", "shutil.move"},

	// --- File delete (destructive) ---
	{regexp.MustCompile(`os\.remove\b`), "file_delete", "destructive", "os.remove call"},
	{regexp.MustCompile(`os\.unlink\b`), "file_delete", "destructive", "os.unlink call"},
	{regexp.MustCompile(`os\.rmdir\b`), "file_delete", "destructive", "os.rmdir call"},
	{regexp.MustCompile(`shutil\.rmtree`), "file_delete", "destructive", "shutil.rmtree call"},

	// --- Subprocess (admin) ---
	{regexp.MustCompile(`subprocess\.(run|Popen|call|check_output|check_call)\s*\(`), "subprocess", "admin", "subprocess invocation"},
	{regexp.MustCompile(`os\.system\s*\(`), "subprocess", "admin", "os.system call"},
	{regexp.MustCompile(`os\.popen\s*\(`), "subprocess", "admin", "os.popen call"},
	{regexp.MustCompile(`os\.exec`), "subprocess", "admin", "os.exec call"},

	// --- Restricted imports (admin) ---
	{regexp.MustCompile(`import\s+ctypes`), "restricted_import", "admin", "ctypes import"},
	{regexp.MustCompile(`import\s+importlib`), "restricted_import", "admin", "importlib import"},
	{regexp.MustCompile(`import\s+__builtins__`), "restricted_import", "admin", "__builtins__ import"},

	// --- Env access (read) ---
	{regexp.MustCompile(`os\.environ`), "env_access", "read", "os.environ access"},
	{regexp.MustCompile(`os\.getenv\s*\(`), "env_access", "read", "os.getenv call"},

	// --- Dangerous patterns (admin) ---
	{regexp.MustCompile(`\beval\s*\(`), "system_call", "admin", "eval() call"},
	{regexp.MustCompile(`\bexec\s*\(`), "system_call", "admin", "exec() call"},
	{regexp.MustCompile(`\bcompile\s*\(`), "system_call", "admin", "compile() call"},
	{regexp.MustCompile(`__import__\s*\(`), "system_call", "admin", "__import__() call"},

	// --- Obfuscated execution patterns (destructive) ---
	// exec/eval with base64-decoded payload
	{regexp.MustCompile(`\bexec\s*\(\s*base64\.b64decode\b`), "obfuscated_exec", "destructive", "exec(base64.b64decode(...)) obfuscated execution"},
	{regexp.MustCompile(`\bexec\s*\(\s*codecs\.decode\b`), "obfuscated_exec", "destructive", "exec(codecs.decode(...)) obfuscated execution"},
	{regexp.MustCompile(`\bexec\s*\(\s*bytes\.fromhex\b`), "obfuscated_exec", "destructive", "exec(bytes.fromhex(...)) obfuscated execution"},
	{regexp.MustCompile(`\beval\s*\(\s*base64\.b64decode\b`), "obfuscated_exec", "destructive", "eval(base64.b64decode(...)) obfuscated execution"},
	{regexp.MustCompile(`\beval\s*\(\s*codecs\.decode\b`), "obfuscated_exec", "destructive", "eval(codecs.decode(...)) obfuscated execution"},
	{regexp.MustCompile(`\beval\s*\(\s*bytes\.fromhex\b`), "obfuscated_exec", "destructive", "eval(bytes.fromhex(...)) obfuscated execution"},
	// eval wrapping compile with exec mode
	{regexp.MustCompile(`\beval\s*\(\s*compile\s*\(`), "obfuscated_exec", "destructive", "eval(compile(...)) obfuscated execution"},
	// Dynamic import of builtins + exec
	{regexp.MustCompile(`__import__\s*\(\s*['"]builtins['"]\s*\)\s*\.\s*exec\b`), "obfuscated_exec", "destructive", "__import__('builtins').exec(...) obfuscated execution"},
	{regexp.MustCompile(`__import__\s*\(\s*['"]builtins['"]\s*\)\s*\.\s*eval\b`), "obfuscated_exec", "destructive", "__import__('builtins').eval(...) obfuscated execution"},
	// subprocess with base64/encoded args
	{regexp.MustCompile(`subprocess\.\w+\s*\([^)]*base64\.b64decode\b`), "obfuscated_exec", "destructive", "subprocess with base64-decoded args"},
	{regexp.MustCompile(`subprocess\.\w+\s*\([^)]*codecs\.decode\b`), "obfuscated_exec", "destructive", "subprocess with codecs-decoded args"},
	{regexp.MustCompile(`subprocess\.\w+\s*\([^)]*bytes\.fromhex\b`), "obfuscated_exec", "destructive", "subprocess with bytes.fromhex args"},
	// pickle.loads with encoded input
	{regexp.MustCompile(`pickle\.loads\s*\(\s*base64\.b64decode\b`), "obfuscated_exec", "destructive", "pickle.loads(base64.b64decode(...)) deserialization attack"},
	{regexp.MustCompile(`pickle\.loads\s*\(\s*codecs\.decode\b`), "obfuscated_exec", "destructive", "pickle.loads(codecs.decode(...)) deserialization attack"},
	{regexp.MustCompile(`pickle\.loads\s*\(\s*bytes\.fromhex\b`), "obfuscated_exec", "destructive", "pickle.loads(bytes.fromhex(...)) deserialization attack"},
	// os.system with base64/encoded args
	{regexp.MustCompile(`os\.system\s*\(\s*base64\.b64decode\b`), "obfuscated_exec", "destructive", "os.system(base64.b64decode(...)) obfuscated execution"},
	{regexp.MustCompile(`os\.system\s*\(\s*codecs\.decode\b`), "obfuscated_exec", "destructive", "os.system(codecs.decode(...)) obfuscated execution"},
	{regexp.MustCompile(`os\.system\s*\(\s*bytes\.fromhex\b`), "obfuscated_exec", "destructive", "os.system(bytes.fromhex(...)) obfuscated execution"},
	// exec/eval with zlib/gzip decompression chain
	{regexp.MustCompile(`\bexec\s*\(\s*zlib\.decompress\b`), "obfuscated_exec", "destructive", "exec(zlib.decompress(...)) compressed obfuscated execution"},
	{regexp.MustCompile(`\bexec\s*\(\s*gzip\.decompress\b`), "obfuscated_exec", "destructive", "exec(gzip.decompress(...)) compressed obfuscated execution"},

	// --- Trusted library eval delegation (attacker-controlled input to eval-capable APIs) ---
	{regexp.MustCompile(`pandas\.eval\s*\(`), "eval_delegation", "destructive", "pandas.eval() with potential attacker input"},
	{regexp.MustCompile(`pd\.eval\s*\(`), "eval_delegation", "destructive", "pd.eval() with potential attacker input"},
	{regexp.MustCompile(`sympy\.parse_expr\s*\(`), "eval_delegation", "destructive", "sympy.parse_expr() with potential attacker input"},
	{regexp.MustCompile(`sympy\.sympify\s*\(`), "eval_delegation", "destructive", "sympy.sympify() with potential attacker input"},
	{regexp.MustCompile(`numpy\.vectorize\s*\(`), "eval_delegation", "write", "numpy.vectorize() can execute arbitrary callables"},
	{regexp.MustCompile(`ast\.literal_eval\s*\(`), "eval_delegation", "read", "ast.literal_eval() — safe for literals but often confused with eval()"},
	{regexp.MustCompile(`yaml\.load\s*\([^)]*\)`), "eval_delegation", "destructive", "yaml.load() without SafeLoader executes arbitrary Python"},
	{regexp.MustCompile(`pickle\.loads?\s*\(`), "eval_delegation", "destructive", "pickle deserialization executes arbitrary code"},
	{regexp.MustCompile(`marshal\.loads?\s*\(`), "eval_delegation", "destructive", "marshal deserialization can execute code"},
	{regexp.MustCompile(`jsonpickle\.decode\s*\(`), "eval_delegation", "destructive", "jsonpickle.decode() executes arbitrary Python objects"},
}

// Analyze scans Python source code for risky operations.
func (a *PythonAnalyzer) Analyze(code string) []Operation {
	var ops []Operation
	for _, p := range pythonPatterns {
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
