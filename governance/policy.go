package governance

// StaticPolicyRule defines a simple allow/deny rule evaluated before the
// full PolicyEval engine. Mirrors securemcp.PolicyRule.
type StaticPolicyRule struct {
	Name   string `json:"name" yaml:"name"`
	Tool   string `json:"tool" yaml:"tool"`
	Action string `json:"action" yaml:"action"` // "allow", "deny", "audit"
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
}
