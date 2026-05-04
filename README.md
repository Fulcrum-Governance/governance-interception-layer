# Governance Interception Layer (GIL)

> The out-of-process enforcement boundary of the Fulcrum governance kernel. Protocol-agnostic pre-execution control for AI agent tool calls.

[![Go Reference](https://pkg.go.dev/badge/github.com/fulcrum-governance/gil.svg)](https://pkg.go.dev/github.com/fulcrum-governance/gil)
[![Go Report Card](https://goreportcard.com/badge/github.com/fulcrum-governance/gil)](https://goreportcard.com/report/github.com/fulcrum-governance/gil)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

## What is GIL?

GIL is the out-of-process enforcement boundary of the Fulcrum governance kernel — a portable, typed, pre-execution control plane that sits between intent and action. As a Go library, GIL evaluates agent tool calls against trust state, static policies, domain interceptors, and a portable policy engine — before those calls are forwarded to the underlying tool. It runs out-of-process as part of an MCP proxy, CLI wrapper, or code-execution gateway, so the governed agent cannot bypass or disable it — provided GIL is the sole route to the tool (i.e., the agent's network and process boundary cannot reach the tool directly). GIL is the open-source enforcement core of [Fulcrum](https://fulcrumlayer.io); it handles the decision path and leaves intelligence (semantic analysis, Bayesian trust scoring, cost modelling) to the commercial kernel surface.

## Architecture

```
Agent Request
     │
     ▼
┌─────────────────┐   Stage 1:  Trust / circuit-breaker check (optional)
│ TrustChecker    │            Isolated or Terminated → deny
└────────┬────────┘
         │
         ▼
┌─────────────────┐   Stage 2:  Static allow/deny rules on tool name
│ Static Policies │            Fastest path; no I/O
└────────┬────────┘
         │
         ▼
┌─────────────────┐   Stage 3:  Domain-specific interceptors by tool name
│  Interceptors   │            (e.g. SQL guard, filesystem whitelist)
└────────┬────────┘
         │
         ▼
┌─────────────────┐   Stage 4:  Portable PolicyEval engine
│   PolicyEval    │            Declarative rules with conditions
└────────┬────────┘
         │
         ▼
  GovernanceDecision  (allow | deny | warn | escalate | require_approval)
         │
         ▼
  AuditPublisher     Emitted on every evaluation, allow or deny
```

Every stage returns early on a terminal decision. Audit events fire regardless
of outcome.

## Quick Start

```go
package main

import (
	"context"
	"fmt"

	"github.com/fulcrum-governance/gil/governance"
)

func main() {
	cfg := governance.PipelineConfig{
		StaticPolicies: []governance.StaticPolicyRule{
			{Name: "block-rm", Tool: "rm", Action: "deny", Reason: "destructive"},
		},
	}
	pipeline := governance.NewPipeline(cfg, nil, nil, nil)

	req := &governance.GovernanceRequest{
		ToolName:  "rm",
		Transport: governance.TransportCLI,
		TenantID:  "tenant-1",
	}
	decision, err := pipeline.Evaluate(context.Background(), req)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s — %s\n", decision.Action, decision.Reason)
}
```

```
$ go run main.go
deny — destructive
```

## Transport Adapters

| Adapter | Package | Handles |
|---|---|---|
| MCP | `adapters/mcp` | JSON-RPC `tools/call` requests from Model Context Protocol servers |
| CLI | `adapters/cli` | Shell commands including pipe chains, with a risk classifier |
| Code exec | `adapters/codeexec` | Python and JavaScript source submitted to a sandbox, with obfuscation analysis |
| gRPC | `adapters/grpc` | gRPC unary calls via a server interceptor (separate module) |
| A2A *(experimental)* | `adapters/a2a` | Google Agent-to-Agent protocol task messages — adapter governs the decision only; `ForwardGoverned`, `InspectResponse`, and `EmitGovernanceMetadata` are no-ops in the current implementation, so the full transport lifecycle is not yet at parity with MCP/CLI/CodeExec |
| Webhook | `adapters/webhook` | HTTP webhook tool-call payloads |

Each adapter implements the `governance.TransportAdapter` interface. Adding a
new transport is a matter of satisfying that interface — see
[ARCHITECTURE.md](./ARCHITECTURE.md#adding-a-new-transport-adapter).

The gRPC adapter lives in its own Go module under `adapters/grpc/` so that
`google.golang.org/grpc` does not propagate into the root dependency tree.
The other adapters use only stdlib and sibling packages.

## HTTP Middleware

GIL ships an HTTP middleware for reverse-proxy deployments. Wrap any
downstream handler and every request is evaluated through the pipeline
before it is forwarded.

```go
middleware := governance.NewMiddleware(pipeline, downstream, governance.MiddlewareConfig{})
http.ListenAndServe(":8080", middleware)
```

Denied requests return HTTP 403 with a JSON body of `{action, reason,
request_id}`. Every response — allow or deny — carries `X-Governance-Action`,
`X-Governance-Reason`, and `X-Governance-Envelope-ID` headers so clients can
read the verdict without parsing the body. See
[`examples/http-middleware`](./examples/http-middleware).

## Logging

GIL ships a `SlogAuditPublisher` that writes every governance decision as a
structured record. Allow and warn decisions log at `INFO`; deny, escalate,
and require-approval log at `WARN`.

```go
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
auditor := governance.NewSlogAuditPublisher(logger)
pipeline := governance.NewPipeline(cfg, nil, nil, auditor)
```

All standard fields are attached as `slog.Attr` values (request_id,
transport, tool_name, action, reason, agent_id, tenant_id, trust_score,
envelope_id, timestamp) so they index cleanly in any structured sink.

## Dry-Run Mode

Roll out governance in audit-only mode before enforcing. With `DryRun: true`,
the pipeline evaluates every stage normally but converts any terminal deny
into an allow. The decision carries `DryRun: true` and a reason prefixed
with `DRY-RUN would deny:` so the audit trail still reflects what would
have been blocked.

```go
cfg := governance.PipelineConfig{
    DryRun:         true,
    StaticPolicies: rules,
}
pipeline := governance.NewPipeline(cfg, nil, nil, auditor)
```

The HTTP middleware also emits an `X-Governance-Dry-Run: true` header on
any response that was converted from deny to allow.

## Rate Limiting

The `interceptors` package ships a token-bucket rate limiter with three
keying strategies (by agent, by tool, or by the `agent:tool` combination).

```go
rl := interceptors.NewRateLimiter(interceptors.RateLimitConfig{
    MaxRequests: 100,
    Window:      time.Minute,
})
pipeline.RegisterInterceptor("search", rl.ForAgent())
```

The limiter has zero external dependencies and is safe for concurrent use.
See [`examples/rate-limit`](./examples/rate-limit).

## Static Policy Glob Patterns

Static policy rules match the `Tool` field against `GovernanceRequest.ToolName`
using `path.Match` semantics. Exact names match, `*` and the empty string
match everything, and the `*` / `?` / `[abc]` glob operators are supported.
Malformed patterns are treated as non-matching rather than crashing the
pipeline.

```go
{Name: "deny-all-db-writes", Tool: "database_*", Action: "deny", Reason: "writes routed through approval"}
```

## Examples

| Directory | What it shows |
|---|---|
| [`examples/simple`](./examples/simple) | Minimal pipeline with two static rules |
| [`examples/mcp-proxy`](./examples/mcp-proxy) | MCP adapter parsing a JSON-RPC payload |
| [`examples/custom-interceptor`](./examples/custom-interceptor) | Domain interceptor composed with a static policy |
| [`examples/redis-trust`](./examples/redis-trust) | Redis-backed `TrustChecker` implementation |
| [`examples/http-middleware`](./examples/http-middleware) | HTTP reverse-proxy middleware with structured audit logging |
| [`examples/rate-limit`](./examples/rate-limit) | Token-bucket rate limiter wired as an interceptor |

Each example is a standalone Go module with its own `go.mod`. Run any of them
with `go run main.go` from its directory.

## How GIL differs from Microsoft AGT

Microsoft's [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
addresses a related problem. The two projects choose different trade-offs.

| | GIL | Microsoft AGT |
|---|---|---|
| Enforcement topology | Out-of-process proxy or wrapper | In-process library call |
| Bypassable by the agent | No, in the out-of-process proxy topology (agent talks to a different address); applies only when GIL is the sole route to the tool | Possible if the agent controls the process |
| Language | Go | Python |
| Primary surface | MCP / CLI / code-exec | Python SDK calls |
| Scope | Pre-execution enforcement of tool calls | End-to-end agent governance framework |
| Intelligence | Decision engine only (allow/deny/warn/escalate) | Includes safety classifiers and guardrails |

GIL is narrower on purpose: it is the part of the governance stack that must
run outside the agent to be trustworthy. If you are writing a pure-Python
single-process agent and trust it not to disable its own guardrails, AGT may
be a better fit.

## Interfaces

The governance package exports four interfaces that define every extension
point:

- **`TrustChecker`** — returns the current trust state for an agent. Implement
  this to wire GIL to your circuit-breaker or reputation system. `nil` is
  accepted; Stage 1 is skipped.
- **`TransportAdapter`** — the contract each transport satisfies. `ParseRequest`
  converts a protocol-specific payload into a `GovernanceRequest`,
  `ForwardGoverned` relays an allowed request, `InspectResponse` examines
  tool output, `EmitGovernanceMetadata` attaches headers to the response.
  Per-method requirements, no-op semantics, and integration patterns for
  cross-repo consumers (fulcrum-io MCP/CLI/code-exec proxies, fulcrum-trust
  LangGraph adapter) are documented in
  [docs/ADAPTER_CONTRACT.md](./docs/ADAPTER_CONTRACT.md).
- **`Interceptor`** — `func(ctx, *GovernanceRequest) (*InterceptorResult, error)`.
  Register one per tool name via `Pipeline.RegisterInterceptor`. Return `nil`
  to decline and continue the pipeline.
- **`AuditPublisher`** — `Publish(ctx, AuditEvent)`. GIL calls this after every
  evaluation. The default is a no-op; a production deployment typically wires
  this to NATS, Kafka, or a log sink.

Full signatures live in [`governance/`](./governance/).

## Part of the Fulcrum Architecture

Fulcrum is built as four coordinated repositories. This repo provides the
out-of-process enforcement boundary; the core runtime owns multi-tenant
orchestration and operator surfaces; the trust engine tracks agent-pair
reputation; and the formal core publishes machine-checkable proof artifacts.

| Repo | Role | License |
|------|------|---------|
| [`fulcrum-io`](https://github.com/Fulcrum-Governance/fulcrum-io) | Runtime control plane: policy engine, envelope, Foundry, MCP proxy, dashboard | BSL 1.1 |
| **`governance-interception-layer`** (this repo) | Out-of-process enforcement boundary: transport adapters, 4-stage pipeline | Apache 2.0 |
| [`fulcrum-trust`](https://github.com/Fulcrum-Governance/fulcrum-trust) | Trust engine: Beta(α,β) evaluator, circuit breaker, LangGraph adapter | Apache 2.0 |
| [`Fulcrum-Proofs`](https://github.com/Fulcrum-Governance/Fulcrum-Proofs) | Formal core: Lean 4 proofs, claim ledger, theorem inventory | MIT |

Project docs: [Contributing](./CONTRIBUTING.md) · [Security](./SECURITY.md) · [Changelog](./CHANGELOG.md) · [Code of Conduct](./CODE_OF_CONDUCT.md) · [Citation](./CITATION.cff)

GIL is the open-source enforcement layer. The full kernel adds Lean 4 formal verification for policy invariants, Bayesian trust scoring with Beta distributions, per-tenant cost modelling, multi-agent workflow orchestration, and managed multi-tenant infrastructure.

- Website: [fulcrumlayer.io](https://fulcrumlayer.io)
- Companion paper: *Formal Trust and Safety Guarantees for Autonomous Multi-Agent Systems* (preprint forthcoming)

## License

Apache 2.0 — see [LICENSE](./LICENSE).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). For security issues, see
[SECURITY.md](./SECURITY.md).
