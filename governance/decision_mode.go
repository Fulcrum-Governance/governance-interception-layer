package governance

// DecisionMode labels the epistemic confidence level of a governance decision.
// Every decision should carry an explicit mode so operators, auditors, and
// downstream systems know what kind of confidence they are looking at.
//
// The four modes are mutually exclusive and exhaustive for decisions that
// originate inside the Fulcrum governance stack:
//
//   - deterministic → static rule / deterministic code path
//   - classified    → probabilistic evaluator (e.g., Semantic Judge)
//   - proved        → machine-checkable formal proof
//   - human_approved → human reviewer approved the action
//
// The GIL pipeline produces only deterministic and classified decisions.
// The proved and human_approved modes are set by the upstream Foundry layer
// (fulcrum-io) when Lean 4 verification or human review occurs.
type DecisionMode string

const (
	// DecisionModeDeterministic indicates the decision was made by static
	// policy rule matching — no probabilistic inference involved.
	DecisionModeDeterministic DecisionMode = "deterministic"

	// DecisionModeClassified indicates the decision was made by a semantic
	// evaluator (e.g., LLM-based Semantic Judge) — probabilistic.
	DecisionModeClassified DecisionMode = "classified"

	// DecisionModeProved indicates the decision is backed by a machine-checkable
	// formal proof (e.g., Lean 4 budget safety invariant).
	DecisionModeProved DecisionMode = "proved"

	// DecisionModeHumanApproved indicates a human operator reviewed and
	// approved the action.
	DecisionModeHumanApproved DecisionMode = "human_approved"
)

// Valid returns true if the decision mode is one of the four recognized
// values. The empty-string zero value returns false so unset fields can be
// detected programmatically.
func (m DecisionMode) Valid() bool {
	switch m {
	case DecisionModeDeterministic, DecisionModeClassified,
		DecisionModeProved, DecisionModeHumanApproved:
		return true
	}
	return false
}
