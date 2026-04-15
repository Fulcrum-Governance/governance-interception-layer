// Package codeexec provides the code-execution transport adapter for the
// Governance Interception Layer. It governs agents that generate and execute
// code in sandboxed environments by analysing source text for risky operations
// and mapping them to governance actions.
package codeexec

// Operation describes a single risky operation detected in source code.
type Operation struct {
	Type      string // network_call, file_read, file_write, file_delete, subprocess, restricted_import, env_access, system_call
	Detail    string // human-readable description of the match
	RiskLevel string // read, write, admin, destructive
}

// Analyzer inspects source code and returns the set of potentially risky
// operations it contains. Implementations are language-specific.
type Analyzer interface {
	Analyze(code string) []Operation
}

// riskOrder maps risk levels to a numeric ordering so we can compare them.
var riskOrder = map[string]int{
	"read":        0,
	"write":       1,
	"admin":       2,
	"destructive": 3,
}

// HighestOperationRisk returns the highest risk level across a set of
// operations. If ops is empty the default is "read".
func HighestOperationRisk(ops []Operation) string {
	highest := "read"
	for _, op := range ops {
		if riskOrder[op.RiskLevel] > riskOrder[highest] {
			highest = op.RiskLevel
		}
	}
	return highest
}
