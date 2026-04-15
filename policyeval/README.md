# policyeval

Portable, dependency-free policy evaluation engine. Designed to be embedded in MCP proxies, SDKs, and any Go service that needs to govern agent tool calls before execution. Shipped as part of the Governance Interception Layer (GIL).

## Overview

The `policyeval` package provides a thread-safe policy evaluator that operates entirely in-memory with **no infrastructure dependencies** (no database, Redis, or NATS required). This enables consistent policy evaluation behavior across all deployment contexts:

- **MCP Proxy**: Intercepts JSON-RPC tool calls
- **SDK Instrumentation**: Auto-governs framework executions
- **Fulcrum Server**: Central policy evaluation

## Key Types

### Evaluator

The main policy evaluation engine:

```go
type Evaluator struct {
    // Thread-safe, sorted by priority (highest first)
}

// Create with options
evaluator := policyeval.NewEvaluator(policies,
    policyeval.WithMaxEvaluationTime(10*time.Millisecond),
    policyeval.WithLogger(logger),
    policyeval.WithStopOnDeny(true),
)

// Evaluate policies against a request
decision, err := evaluator.Evaluate(ctx, &policyeval.EvaluationRequest{
    TenantID:   "tenant-123",
    UserID:     "user-456",
    ToolNames:  []string{"file_read"},
    InputText:  "Read /etc/passwd",
})
```

### Decision

The result of policy evaluation:

```go
type Decision struct {
    Action               ActionType          // allow, deny, escalate, warn, require_approval
    MatchedPolicy        *policyeval.Policy    // Policy that produced this decision
    MatchedRules         []*RuleMatch        // Rules that matched
    Actions              []*policyeval.PolicyAction
    Reason               string              // Human-readable explanation
    EvaluationDurationMs int64
    EscalationReason     string              // For ActionEscalate
}
```

### ActionType

Possible evaluation outcomes:

| Action | Description |
|--------|-------------|
| `ActionAllow` | Permit the action to proceed |
| `ActionDeny` | Block the action |
| `ActionEscalate` | Requires phone-home check (e.g., Semantic Judge) |
| `ActionWarn` | Allow but log a warning |
| `ActionRequireApproval` | Requires human approval before proceeding |

### EvaluationRequest

Context for policy evaluation:

```go
type EvaluationRequest struct {
    TenantID    string
    UserID      string
    UserRoles   []string
    WorkflowID  string
    EnvelopeID  string
    Phase       policyeval.ExecutionPhase  // PRE, MID, POST
    ModelID     string
    ToolNames   []string
    InputText   string
    OutputText  string
    Attributes  map[string]string  // Custom key-value pairs
}
```

## Condition Types

The evaluator supports multiple condition types:

| Type | Description |
|------|-------------|
| `FIELD_MATCH` | Exact field comparison (equals, not equals) |
| `REGEX` | Regular expression matching (cached) |
| `RANGE` | Numeric comparisons (>, <, >=, <=) |
| `IN_LIST` | Check if value is in a list |
| `CONTAINS` | String contains check |
| `STARTS_WITH` | String prefix check |
| `ENDS_WITH` | String suffix check |
| `STATISTICAL_SPIKE` | Z-score based anomaly detection |
| `EXTERNAL_CALL` | HTTP webhook (disabled by default) |
| `SEMANTIC` | Requires server escalation for LLM evaluation |
| `LOGICAL` | AND/OR/NOT combinations |

## Usage Example

```go
package main

import (
    "context"
    "log"

    "github.com/fulcrum-governance/gil/policyeval"
)

func main() {
    // Create policies
    policies := []*policyeval.Policy{
        {
            PolicyId: "block-sensitive-files",
            TenantId: "tenant-123",
            Status:   policyeval.PolicyStatus_POLICY_STATUS_ACTIVE,
            Priority: 100,
            Rules: []*policyeval.PolicyRule{
                {
                    RuleId:  "rule-1",
                    Name:    "Block /etc/passwd access",
                    Enabled: true,
                    Conditions: []*policyeval.PolicyCondition{
                        {
                            ConditionType: policyeval.ConditionType_CONDITION_TYPE_CONTAINS,
                            Field:         "input.text",
                            Value:         &policyeval.PolicyCondition_StringValue{StringValue: "/etc/passwd"},
                        },
                    },
                    Actions: []*policyeval.PolicyAction{
                        {ActionType: policyeval.PolicyActionType_ACTION_TYPE_DENY},
                    },
                },
            },
        },
    }

    // Create evaluator
    evaluator := policyeval.NewEvaluator(policies,
        policyeval.WithMaxEvaluationTime(10*time.Millisecond),
        policyeval.WithStopOnDeny(true),
    )

    // Evaluate
    decision, err := evaluator.Evaluate(context.Background(), &policyeval.EvaluationRequest{
        TenantID:  "tenant-123",
        InputText: "Read the contents of /etc/passwd",
    })
    if err != nil {
        log.Fatalf("Evaluation error: %v", err)
    }

    log.Printf("Decision: %s - %s", decision.Action, decision.Reason)
}
```

## Configuration Options

```go
// Set maximum evaluation time (default: 10ms)
policyeval.WithMaxEvaluationTime(10 * time.Millisecond)

// Set logger for debug/warning messages
policyeval.WithLogger(myLogger)

// Enable external HTTP calls for conditions (default: false)
policyeval.WithExternalCallsEnabled(true)

// Stop evaluating after first deny (default: true)
policyeval.WithStopOnDeny(true)
```

## Security Features

- **SSRF Protection**: External calls validate URLs against blocked IP ranges and hostnames
- **Regex Cache**: Compiled regex patterns are cached (max 1000) for performance
- **No Secrets in Memory**: Policies don't contain credentials
- **Fail-Closed for Semantic**: Semantic conditions escalate to server (require LLM)

## Performance

- Target: <10ms P99 evaluation time
- Typical: <1ms for simple policies
- Regex caching reduces repeated pattern compilation
- Policy sorting by priority enables early termination

## Testing

```bash
# Run tests
go test ./policyeval/... -v

# With coverage
go test ./policyeval/... -cover

# Current coverage: 97.4%
```

## Dependencies

- Policy types are declared in-package (`types.go`) — no protobuf runtime required
- No external infrastructure (Redis, NATS, database)

## Related Packages

- [`governance`](../governance/) — the 4-stage pipeline that uses this evaluator in its PolicyEval stage
- [`adapters/mcp`](../adapters/mcp/), [`adapters/cli`](../adapters/cli/), [`adapters/codeexec`](../adapters/codeexec/) — transport adapters that feed the pipeline
