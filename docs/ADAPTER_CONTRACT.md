# Adapter Contract

This document describes what an implementation of `governance.TransportAdapter`
is required to do, what it is allowed to no-op, and how cross-repo consumers
integrate with the interface. It complements [`ARCHITECTURE.md`](../ARCHITECTURE.md)
by focusing on the contract itself rather than the surrounding pipeline.

The interface is defined in
[`governance/adapter.go`](../governance/adapter.go) and intentionally has only
five methods. The split between "real work" and "defensive glue" is deliberate
— most adapters should only need to implement `Type()` and `ParseRequest()`
in earnest.

## Interface

```go
type TransportAdapter interface {
    Type() TransportType
    ParseRequest(ctx context.Context, raw any) (*GovernanceRequest, error)
    ForwardGoverned(ctx context.Context, req *GovernanceRequest, decision *GovernanceDecision) (*ToolResponse, error)
    InspectResponse(ctx context.Context, resp *ToolResponse) (*ResponseInspection, error)
    EmitGovernanceMetadata(ctx context.Context, resp *ToolResponse, decision *GovernanceDecision) error
}
```

## Method-by-method contract

| Method | Status | Required behaviour |
|---|---|---|
| `Type()` | **required** | Return one of the `TransportType` constants in [`governance/request.go`](../governance/request.go). Must be stable across calls. |
| `ParseRequest` | **required (real work)** | Convert protocol-specific input into a `GovernanceRequest`. Failure must return a `governance.ParseError` (use `governance.NewParseError`). See "ParseRequest contract" below. |
| `ForwardGoverned` | **optional / often a stub** | Forward the governed call to the downstream tool *only* if your adapter owns the transport. Existing adapters whose forwarding is handled elsewhere return `nil, nil` (webhook, gRPC, A2A) or a fixed error explaining who owns forwarding (MCP, CLI, codeexec). Do not perform side effects that the caller did not ask for. |
| `InspectResponse` | **optional** | Examine `ToolResponse.Content` for governance concerns (size limits, sensitive-data patterns, exit codes). Adapters with no opinion return `&ResponseInspection{Safe: true}, nil`. |
| `EmitGovernanceMetadata` | **optional** | Attach the governance decision's `Action`, `EnvelopeID`, and `RequestID` to the response so callers can read the verdict without parsing the body. Adapters whose host (e.g. an HTTP handler) writes governance headers directly may return `nil`. |

A "no-op" implementation must still satisfy these signatures:

```go
func (a *Adapter) ForwardGoverned(_ context.Context, _ *governance.GovernanceRequest, _ *governance.GovernanceDecision) (*governance.ToolResponse, error) {
    return nil, nil
}

func (a *Adapter) InspectResponse(_ context.Context, _ *governance.ToolResponse) (*governance.ResponseInspection, error) {
    return &governance.ResponseInspection{Safe: true}, nil
}

func (a *Adapter) EmitGovernanceMetadata(_ context.Context, _ *governance.ToolResponse, _ *governance.GovernanceDecision) error {
    return nil
}
```

Returning `nil` from `InspectResponse` instead of a benign result is permitted
(the pipeline tolerates it), but populated results are easier to log and audit.

## ParseRequest contract

`ParseRequest` is the only method that requires real work. Every adapter must:

1. **Accept multiple input shapes.** The shipped adapters all accept the typed
   protocol struct (e.g. `*ToolCallInput` for MCP), the same struct by value,
   `json.RawMessage`, and `[]byte`. New adapters should follow the same pattern
   so the proxy layer can pass whatever it has on hand.
2. **Validate required protocol fields.** Empty tool / method / action names
   are protocol errors and must surface as `ParseError`, not as a request that
   silently reaches the pipeline with empty fields.
3. **Map identity.** `AgentID`, `TenantID`, and (where applicable) `TraceID`
   must be populated from the inbound message; fall back to the adapter's
   configured `DefaultTenantID` when the caller did not set one.
4. **Generate `RequestID`.** Use `uuid.New().String()` per call. Do not reuse
   the protocol's correlation ID — that goes in `TraceID`.
5. **Set `Transport`** to the same value `Type()` returns.
6. **Optionally set `Action`.** Adapters that have a richer notion of action
   (e.g. CLI `read`/`write`/`destructive`, code-exec operation classes) should
   compute it and put it in `Action`. Adapters without that concept use a
   constant string (e.g. `"a2a/task"`, `"webhook/invoke"`).
7. **Return `ParseError` for unknown input types.** Use
   `governance.NewParseError(transport, msg, err)`. Do not panic and do not
   return a generic `error` — the proxy layer distinguishes parse errors from
   pipeline faults.

The shipped adapters under [`adapters/`](../adapters/) are the canonical
worked examples.

## Fail-closed expectations

Adapters do not decide policy outcomes — that is the pipeline's job. But the
adapter does decide whether the pipeline runs at all. The implications:

- A `ParseRequest` error means the request never reaches `Pipeline.Evaluate`.
  The caller is responsible for converting that error into a 400-class
  protocol-level failure (HTTP 400, gRPC `InvalidArgument`, etc.). The webhook
  `Handler` and gRPC `UnaryInterceptor` shipped with GIL do this.
- `ForwardGoverned` runs only after the pipeline returns `Allowed()`. An error
  from forwarding does not retroactively allow a denied call.
- `InspectResponse` runs after the tool produced a response. It is an audit
  hook, not an enforcement hook — denying based on response content requires a
  pipeline rerun (rare; most callers log the inspection and move on).

## Cross-repo consumers

Three consumers integrate against this interface today, each in a different
process and language:

### `fulcrum-io` MCP / CLI / code-exec proxies

Repo: [`fulcrum-io`](https://fulcrumlayer.io) (`/internal/adapters/mcp`,
`/internal/adapters/cli`, `/internal/adapters/codeexec`).

The runtime control plane wraps the GIL adapters in production-grade
forwarding code: the MCP adapter feeds the `mcpproxy` JSON-RPC interceptor,
the CLI adapter is invoked from the agent runtime command bridge, and the
code-exec adapter is invoked from the Python/JavaScript sandbox gateway. In
every case, GIL is the parsing and decision layer; the surrounding fulcrum-io
service owns the actual transport I/O. That is why the shipped GIL adapters
return a fixed error from `ForwardGoverned` rather than attempting to forward
themselves — the consumer must override or wrap.

### `fulcrum-trust` LangGraph adapter

Repo: [`fulcrum-trust`](https://github.com/Fulcrum-Governance/fulcrum-trust)
(`/fulcrum_trust/adapters/langgraph.py`).

LangGraph runs in-process with the agent. The Python adapter does not
implement `TransportAdapter` directly (it is a different interface in a
different language) — instead it converts each LangGraph tool invocation into
a JSON payload that goes to a fulcrum-io endpoint, which in turn runs the
appropriate Go adapter. The GIL contract therefore reaches LangGraph through
two hops: LangGraph -> fulcrum-trust IPC bridge -> fulcrum-io -> GIL adapter
-> pipeline. The trust circuit-breaker layer in fulcrum-trust feeds the
pipeline's `TrustChecker` slot.

### Direct consumers (your code)

Any Go service that imports `github.com/fulcrum-governance/gil/governance`
can construct adapters directly. The pattern is:

```go
adapter := mcp.NewAdapter("default-tenant")
req, err := adapter.ParseRequest(ctx, payload)
if err != nil {
    return badRequest(err)
}
decision, err := pipeline.Evaluate(ctx, req)
if err != nil {
    return serverError(err)
}
if !decision.Allowed() {
    return forbidden(decision)
}
resp, err := callTheActualTool(ctx, req)
if err != nil {
    return upstreamError(err)
}
_, _ = adapter.InspectResponse(ctx, resp)
_ = adapter.EmitGovernanceMetadata(ctx, resp, decision)
return ok(resp)
```

The shipped [`webhook.Handler`](../adapters/webhook/adapter.go) and
[`grpc.UnaryInterceptor`](../adapters/grpc/adapter.go) collapse this
pattern into a single function.

## Adding a new adapter

The procedure mirrors
[ARCHITECTURE.md "Adding a new transport adapter"](../ARCHITECTURE.md#adding-a-new-transport-adapter):

1. Create `adapters/<yourname>/adapter.go`.
2. Declare a new `TransportType` constant in
   [`governance/request.go`](../governance/request.go) if your transport is
   not already represented.
3. Implement the contract above. Use the shipped adapters as templates.
4. Add a compile-time check: `var _ governance.TransportAdapter = (*Adapter)(nil)`.
5. Write a table-driven test against `ParseRequest` covering at least one
   success case per accepted input shape and one failure case per validation
   branch.
6. Document the protocol-specific input struct with a brief Go doc comment
   above its declaration.

If your adapter pulls in a heavy dependency (a third-party protocol library),
follow the gRPC adapter's lead and put the package in its own `go.mod` so the
root module stays slim.

## Versioning the contract

The contract is versioned with GIL itself. Breaking changes to the interface
go through a CHANGELOG entry and follow the same major/minor discipline as
the rest of the public API. Adding a new `TransportType` constant is a
backwards-compatible change. Removing methods, adding required methods, or
changing return types are not.
