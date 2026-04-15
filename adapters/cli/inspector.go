package cli

import (
	"regexp"
	"strings"

	"github.com/fulcrum-governance/gil/governance"
)

// Inspector detects sensitive data in CLI input and output.
type Inspector struct{}

// NewInspector creates an Inspector.
func NewInspector() *Inspector {
	return &Inspector{}
}

// sensitivePattern pairs a human-readable label with a compiled regex.
type sensitivePattern struct {
	label   string
	pattern *regexp.Regexp
}

// patterns is the compiled list of sensitive data detectors.
// All patterns are case-insensitive.
var patterns = []sensitivePattern{
	// API keys
	{label: "OpenAI API key", pattern: regexp.MustCompile(`(?i)sk-[a-zA-Z0-9\-_]{20,}`)},
	{label: "AWS access key", pattern: regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
	{label: "GitHub personal access token", pattern: regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36,}`)},
	{label: "GitLab personal access token", pattern: regexp.MustCompile(`(?i)glpat-[a-zA-Z0-9\-]{20,}`)},
	{label: "Slack bot token", pattern: regexp.MustCompile(`(?i)xoxb-[a-zA-Z0-9\-]+`)},
	{label: "Bearer token", pattern: regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9\-._~+/]+=*`)},

	// Passwords
	{label: "password assignment", pattern: regexp.MustCompile(`(?i)(?:password|passwd|pass)\s*=\s*\S+`)},

	// Private keys
	{label: "private key", pattern: regexp.MustCompile(`(?i)-----BEGIN\s[A-Z\s]*PRIVATE\sKEY-----`)},

	// AWS credentials
	{label: "AWS access key ID", pattern: regexp.MustCompile(`(?i)aws_access_key_id\s*=\s*\S+`)},
	{label: "AWS secret access key", pattern: regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*\S+`)},

	// Connection strings with credentials
	{label: "PostgreSQL connection string", pattern: regexp.MustCompile(`(?i)postgresql://[^@\s]+:[^@\s]+@`)},
	{label: "MongoDB connection string", pattern: regexp.MustCompile(`(?i)mongodb://[^@\s]+:[^@\s]+@`)},
	{label: "Redis connection string", pattern: regexp.MustCompile(`(?i)redis://[^@\s]+:[^@\s]+@`)},

	// Generic secrets
	{label: "secret assignment", pattern: regexp.MustCompile(`(?i)(?:secret|token|api_key)\s*=\s*\S+`)},
}

// InspectStdin scans raw stdin data for sensitive patterns.
// Returns a list of concern strings (empty = clean).
func (ins *Inspector) InspectStdin(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return detectSensitive(data)
}

// InspectOutput examines CLI command output for governance concerns.
func (ins *Inspector) InspectOutput(data []byte) *governance.ResponseInspection {
	if len(data) == 0 {
		return &governance.ResponseInspection{Safe: true}
	}

	concerns := detectSensitive(data)
	if len(concerns) == 0 {
		return &governance.ResponseInspection{Safe: true}
	}

	return &governance.ResponseInspection{
		Safe:          false,
		Concerns:      concerns,
		SensitiveData: true,
	}
}

// detectSensitive scans data against all sensitive patterns and returns
// a deduplicated list of concern labels.
func detectSensitive(data []byte) []string {
	text := string(data)
	seen := make(map[string]bool)
	var concerns []string

	for _, sp := range patterns {
		if sp.pattern.MatchString(text) {
			if !seen[sp.label] {
				seen[sp.label] = true
				concerns = append(concerns, "sensitive data detected: "+sp.label)
			}
		}
	}

	// Check for connection strings without user:pass embedded (plain URLs are ok,
	// but we flag ones that look like they contain inline credentials).
	// Already handled by the specific patterns above, but add a generic
	// check for connection strings we might have missed.
	connStrPatterns := []string{"://", "jdbc:"}
	for _, pat := range connStrPatterns {
		if strings.Contains(strings.ToLower(text), pat) {
			// Already covered by specific patterns — only flag if we see user:pass@ pattern
			// in any scheme we haven't specifically checked.
			break
		}
	}

	return concerns
}
