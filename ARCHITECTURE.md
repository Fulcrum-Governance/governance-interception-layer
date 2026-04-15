# GIL Architecture

This document describes the pipeline, interface contracts, and extension
points. It assumes familiarity with the [README](./README.md).

## The four-stage pipeline

Every governance evaluation runs through the same four stages in the same
order. Each stage returns a terminal decision immediately on deny; otherwise
control passes to the next stage. Stages that need data they do not have
(nil `TrustChecker`, no interceptor for the tool, no static rules) are
silent no-ops, not errors.

```
GovernanceRequest
     │
     ▼
Stage 1: Trust check              Skipped when TrustChecker == nil OR
         (TrustChecker)           req.AgentID == "".
                                  Isolated / Terminated   → deny
                                  Evaluating              → score 0.5
                                  CheckAgentState error   → deny (fail-closed)
     │
     ▼
Stage 2: Static policies          Linear scan of StaticPolicyRule list.
                                  Tool matches by exact name, by "*" / "",
                                  or by path.Match glob syntax
                                  ("*", "?", "[abc]"). Malformed patterns
                                  are silently non-matching.
                                  First rule whose Tool matches AND whose
                                  Action == "deny" terminates. Allow rules
                                  fall through to later stages.
     │
     ▼
Stage 3: Domain interceptors      interceptors[req.ToolName](ctx, req)
                                  Returns nil       → continue
                                  Allowed == false  → terminate with result
                                  Error             → deny (fail-closed)
     │
     ▼
Stage 4: PolicyEval engine        policyeval.Evaluator evaluates the request
                                  against all active policies. Actions:
                                    Deny / Escalate / RequireApproval / Warn
                                  Evaluator errors follow fail-closed vs
                                  fail-open as described below.
     │
     ▼
GovernanceDecision → AuditPublisher.Publish → [DryRun conversion] → return
```

### Dry-run mode

`PipelineConfig.DryRun` enables audit-only rollout. When set, the pipeline
runs all four stages normally and emits the audit event with the real
decision — then, if the decision was `deny`, converts it to `allow` before
returning. The returned decision carries `DryRun: true` and a reason
prefixed with `DRY-RUN would deny:`. The audit trail therefore reflects
what governance *would* have blocked while the caller observes the
permissive outcome. Use this to validate a new policy before enforcing it.

## Data flow

```
Protocol payload  ──► TransportAdapter.ParseRequest ──► GovernanceRequest
                                                              │
                                                              ▼
                                                      Pipeline.Evaluate
                                                              │
                       AuditPublisher.Publish  ◄──────────────┤
                                                              │
                                                              ▼
                                                     GovernanceDecision
                                                              │
                                                              ▼
                 TransportAdapter.ForwardGoverned ──► downstream tool
                                                              │
                                                              ▼
                                                         ToolResponse
                                                              │
                                                              ▼
                 TransportAdapter.InspectResponse
                 TransportAdapter.EmitGovernanceMetadata
                                                              │
                                                              ▼
                                                     Protocol response
```

## Interface contracts

### `TransportAdapter`

Defined in [`governance/adapter.go`](./governance/adapter.go).

```go
type TransportAdapter interface {
    Type() TransportType
    ParseRequest(ctx context.Context, raw any) (*GovernanceRequest, error)
    ForwardGoverned(ctx context.Context, req *GovernanceRequest, decision *GovernanceDecision) (*ToolResponse, error)
    InspectResponse(ctx context.Context, resp *ToolResponse) (*ResponseInspection, error)
    EmitGovernanceMetadata(ctx context.Context, resp *ToolResponse, decision *GovernanceDecision) error
}
```

`ParseRequest` is where protocol-specific knowledge lives. Everything else is
defensive glue — if your protocol has no notion of response metadata, return
`nil, nil` from `InspectResponse` and a no-op from `EmitGovernanceMetadata`.

### `TrustChecker`

Defined in [`governance/trust.go`](./governance/trust.go).

```go
type TrustChecker interface {
    CheckAgentState(ctx context.Context, agentID string) (TrustState, error)
}
```

Returning an error is treated as fail-closed. An absent state record is not
an error — return `TrustStateTrusted`. See
[`examples/redis-trust`](./examples/redis-trust) for a reference
implementation.

### `Interceptor`

Defined in [`governance/interceptor.go`](./governance/interceptor.go).

```go
type Interceptor func(ctx context.Context, req *GovernanceRequest) (*InterceptorResult, error)
```

Register one function per tool name via `Pipeline.RegisterInterceptor`.
Return `nil, nil` to decline and let later stages run. Return a non-nil
`InterceptorResult` with `Allowed == false` to block. If you block without
setting `Action`, the pipeline defaults to `"deny"`.

### `AuditPublisher`

Defined in [`governance/audit.go`](./governance/audit.go).

```go
type AuditPublisher interface {
    Publish(ctx context.Context, event AuditEvent)
}
```

`Publish` is fire-and-forget: no return value. Implementations must not block
the caller; if the sink is slow, buffer or drop. The default is a no-op.

## Fail-closed vs fail-open

GIL distinguishes infrastructure faults from policy outcomes. A policy that
denies a call is a *decision*; a crash in the trust backend is a *fault*.

| Fault location | Default behaviour | Rationale |
|---|---|---|
| `TrustChecker.CheckAgentState` returns an error | **Fail-closed (deny)** | Trust unknown. Safer to deny than to let the agent proceed on stale state. |
| `Interceptor` returns an error | **Fail-closed (deny)** | Domain logic is unreachable. The caller registered it because the tool needs it. |
| `policyeval.Evaluator.Evaluate` returns an error | **Per-transport** | Configured via `PipelineConfig.FailClosedTransports`. |

For Stage 4, the transport type decides. Transports listed in
`FailClosedTransports` deny on evaluator errors; all other transports
fall through and allow. A typical deployment marks `TransportCodeExec` and
`TransportMCP` fail-closed and leaves `TransportCLI` fail-open so a flaky
evaluator does not brick an interactive session.

## Adding a new transport adapter

1. Create `adapters/<yourname>/adapter.go`. Declare a new `TransportType`
   constant in the same file or export a helper that returns it.
2. Implement `governance.TransportAdapter`. `ParseRequest` is the only method
   that requires real work; the rest can be stubs until you need them.
3. Map protocol-specific identifiers to `GovernanceRequest` fields:
   - Tool or action name → `ToolName`
   - Principal identity → `AgentID`
   - Multi-tenant scoping → `TenantID`
   - Raw payload (for audit) → `RawPayload`
4. Write a table-driven test that feeds a few representative payloads through
   `ParseRequest` and asserts the expected `GovernanceRequest` values.
5. Wire the adapter in your proxy: call `adapter.ParseRequest`, pass the
   result to `Pipeline.Evaluate`, then branch on `decision.Allowed()`.

Existing adapters under [`adapters/`](./adapters) are worked examples. The
shipped set is:

| Package | Transport | Notes |
|---|---|---|
| `adapters/mcp` | MCP JSON-RPC | |
| `adapters/cli` | Shell commands | Risk classifier + pipe-chain analysis |
| `adapters/codeexec` | Python / JavaScript | Obfuscation detection |
| `adapters/grpc` | gRPC unary | Separate `go.mod` so `google.golang.org/grpc` does not leak into the root module |
| `adapters/a2a` | Google Agent-to-Agent | Task message parsing |
| `adapters/webhook` | HTTP webhooks | JSON payload parser + ready-made handler |

## Writing a custom interceptor

Interceptors are the right extension point for logic that cannot be expressed
as a declarative allow/deny list — SQL parsing, filesystem path allow-lists,
argument-level sanitisation.

```go
func sqlGuard(ctx context.Context, req *governance.GovernanceRequest) (*governance.InterceptorResult, error) {
    sql, _ := req.Arguments["sql"].(string)
    if strings.Contains(strings.ToUpper(sql), "DROP ") {
        return &governance.InterceptorResult{
            Allowed: false,
            Action:  "deny",
            Reason:  "SQL DROP is not permitted",
        }, nil
    }
    return nil, nil // no opinion — continue pipeline
}

pipeline.RegisterInterceptor("database_query", sqlGuard)
```

Guidelines:
- Keep interceptors fast. They run on the hot path of every tool call.
- Do not do network I/O from an interceptor if you can avoid it. If you must,
  bound it with a `context.Context` deadline that the caller owns.
- Return `nil, nil` generously. An interceptor that opines on requests it
  does not understand is a source of surprise denials.
- `Allowed == false` with an empty `Action` defaults to `"deny"`. Set
  `Action` explicitly if you want `"warn"` or `"escalate"`.

[`examples/custom-interceptor`](./examples/custom-interceptor) is a working
version of the snippet above.

## Built-in interceptors

The `interceptors/` package ships production-ready interceptors that use
only stdlib plus the sibling `governance` package.

### Rate limiting

`interceptors.RateLimiter` is a per-key token bucket. Keys can be chosen
at registration time:

| Helper | Key |
|---|---|
| `rl.ForAgent()` | `req.AgentID` |
| `rl.ForTool()` | `req.ToolName` |
| `rl.ForAgentTool()` | `req.AgentID + ":" + req.ToolName` |

Register the returned `Interceptor` under whichever tool name you want to
limit. The limiter is safe for concurrent use and costs one `sync.Mutex`
acquisition per request. See
[`examples/rate-limit`](./examples/rate-limit).
