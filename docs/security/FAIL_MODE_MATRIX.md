# Transport Fail-Mode Matrix

**Status:** v0.1 (audit of existing behavior, not a design proposal)
**Source:** PRD-004. Pipeline at `governance/pipeline.go`.
**Audience:** security reviewers, acquirers, on-call engineers.

This document specifies the exact fail-open / fail-closed behavior of the GIL
governance pipeline for each supported transport and each fault class. It
records what the code **does today**, with source citations. Recommendations
for production defaults are in §3; known gaps are in §6.

**Path conventions:** unqualified `pipeline.go` citations refer to
`governance/pipeline.go`. Adapter citations use the full repo-relative path
(`adapters/<transport>/adapter.go`). Test citations use the full path
(`governance/pipeline_test.go`, `governance/pipeline_coverage_test.go`).

## 1. Pipeline Fail-Mode Architecture

`Pipeline.Evaluate` runs four stages in sequence and always emits exactly one
audit event via a deferred hook (`pipeline.go:118-130`). The staging is:

| # | Stage | Location | Error behavior |
|---|-------|----------|----------------|
| 1 | Trust Check | `pipeline.go:132-150` | **Always fail-closed.** Trust error → deny (`pipeline.go:136-140`). Agent in `ISOLATED`/`TERMINATED` state → deny (`pipeline.go:141-146`). `EVALUATING` state proceeds with trust score 0.5 (`pipeline.go:147-149`). No per-transport override. Stage is skipped entirely when `trustChecker == nil` or `req.AgentID == ""`. |
| 2 | Static Policies | `pipeline.go:152-165` | **No error path.** Glob matching via `path.Match` discards the match error (`pipeline.go:80-89`); malformed patterns are treated as non-matching rather than crashing the pipeline. |
| 3 | Domain Interceptors | `pipeline.go:167-181` | **Always fail-closed.** Interceptor returns an error → deny with reason `interceptor error: %v` (`pipeline.go:169-173`). Interceptor returns `{Allowed: false}` uses its own action/reason; empty action defaults to `deny` (`pipeline.go:174-181`). |
| 4 | PolicyEval | `pipeline.go:183-215` | **Per-transport configurable.** Evaluator error → deny only if `req.Transport` is in `PipelineConfig.FailClosedTransports` (`pipeline.go:189-193`). Otherwise the error is swallowed and the pre-existing `allow` default is returned (`pipeline.go:194-195`). |

The defer-emit hook at `pipeline.go:118-130` is the only place a decision can
be reshaped:

1. `decision.Duration` is recorded.
2. `p.emitAudit(...)` publishes the **original** action to the auditor.
3. **Then** — and only then — if `p.dryRun && decision.Action == "deny"`, the
   action is rewritten to `allow`, `decision.DryRun = true`, and the original
   reason is prefixed with `DRY-RUN would deny:`.

This ordering guarantees that the audit log always reflects what governance
would have blocked, even when dry-run flips the caller-visible action.

## 2. Fail-Mode Matrix

Seven fault classes × six transports. Each cell is one of:

- **DENY** — pipeline sets `decision.Action = "deny"`.
- **ALLOW** — pipeline leaves the default `decision.Action = "allow"`.
- **PASS** — pipeline is not involved; downstream error is surfaced by the
  caller's runtime unchanged.
- **ERR→caller** — adapter `ParseRequest` returns a Go error; the embedding
  runtime (mcpproxy, agent runtime, sandbox runtime) decides what the caller
  sees. Functionally the tool call does not proceed, which is equivalent to
  deny — but the decision and audit event are **not** produced by the GIL
  pipeline.
- **HTTP 400 / codes.Internal** — adapter surfaces a protocol-specific
  fail-closed error before pipeline entry.

| Fault Class | MCP | CLI | Code Exec | gRPC | A2A | Webhook |
|---|---|---|---|---|---|---|
| Trust store unreachable | DENY `pipeline.go:136-140` | DENY `pipeline.go:136-140` | DENY `pipeline.go:136-140` | DENY `pipeline.go:136-140` | DENY `pipeline.go:136-140` | DENY `pipeline.go:136-140` |
| Agent ISOLATED or TERMINATED | DENY `pipeline.go:141-146` | DENY `pipeline.go:141-146` | DENY `pipeline.go:141-146` | DENY `pipeline.go:141-146` | DENY `pipeline.go:141-146` | DENY `pipeline.go:141-146` |
| Adapter parse failure | ERR→caller `adapters/mcp/adapter.go:44-64` | ERR→caller `adapters/cli/adapter.go:52-82` | ERR→caller `adapters/codeexec/adapter.go:52-79` | `codes.Internal` `adapters/grpc/adapter.go:141-143` | ERR→caller `adapters/a2a/adapter.go:51-73` | HTTP 400 `adapters/webhook/adapter.go:139-143` |
| Interceptor error | DENY `pipeline.go:169-173` | DENY `pipeline.go:169-173` | DENY `pipeline.go:169-173` | DENY `pipeline.go:169-173` | DENY `pipeline.go:169-173` | DENY `pipeline.go:169-173` |
| PolicyEval error (transport in `FailClosedTransports`) | DENY `pipeline.go:189-193` | DENY `pipeline.go:189-193` | DENY `pipeline.go:189-193` | DENY `pipeline.go:189-193` | DENY `pipeline.go:189-193` | DENY `pipeline.go:189-193` |
| PolicyEval error (transport NOT in `FailClosedTransports`) | ALLOW `pipeline.go:194-195` | ALLOW `pipeline.go:194-195` | ALLOW `pipeline.go:194-195` | ALLOW `pipeline.go:194-195` | ALLOW `pipeline.go:194-195` | ALLOW `pipeline.go:194-195` |
| Downstream tool error (5xx / non-zero exit) | PASS `adapters/mcp/adapter.go:86-88` | PASS `adapters/cli/adapter.go:120-122` | PASS `adapters/codeexec/adapter.go:112-114` | PASS `adapters/grpc/adapter.go:97-99` | PASS `adapters/a2a/adapter.go:89-92` | PASS `adapters/webhook/adapter.go:100-102` |

**Notes on the matrix:**

- **Adapter parse failure** happens BEFORE the pipeline runs. No audit event
  is emitted by the pipeline in this case, because `Evaluate` is never
  called. The gRPC and webhook adapters embed pipeline invocation in their
  own HTTP/gRPC handlers (`adapters/grpc/adapter.go:131-157`,
  `adapters/webhook/adapter.go:128-177`), which is why they can map
  parse errors to protocol-level fail-closed responses (`codes.Internal`,
  HTTP 400). MCP, CLI, CodeExec, and A2A adapters only provide parsing; the
  embedding runtime (mcpproxy, agent runtime, sandbox runtime, A2A caller)
  is responsible for translating a parse error into a protocol response.

- **PolicyEval error (fail-open row)** is the only cell in the entire matrix
  where the GIL default behavior is ALLOW on error. This is why
  `FailClosedTransports` exists — it lets operators flip this row to DENY
  per security-critical transport.

- **Downstream tool error (PASS row)**: every `ForwardGoverned` method on
  every adapter is a no-op or stub. Forwarding is the responsibility of the
  surrounding runtime (mcpproxy, agent runtime, sandbox runtime, gRPC
  interceptor chain, webhook `Handler()`). The governance decision is
  emitted before forwarding happens, so downstream 5xx or non-zero exit does
  not retroactively change the action in the audit event.

## 3. Recommended `FailClosedTransports` Defaults

`PipelineConfig.FailClosedTransports` is `nil` by default
(`pipeline.go:19-21`), which means **all transports fail-open on PolicyEval
errors unless operators opt in**. Recommended production defaults below. This
is a recommendation, not an enforced policy — the pipeline ships with the
empty default.

| Transport | Recommended | Rationale |
|---|---|---|
| `TransportMCP` | **fail-closed** | Model-facing tool surface; silently allowing on evaluator outage means the governance layer degrades to the pre-GIL state for agent tool calls. This is the single most security-critical row in the matrix. |
| `TransportCodeExec` | **fail-closed** | Arbitrary code execution. A PolicyEval outage that allows-by-default here sidesteps the 21 Python + 9 JavaScript obfuscation analyzers (`adapters/codeexec/analyzer_python.go`, `analyzer_javascript.go`). |
| `TransportCLI` | **fail-closed** | Command execution with parsed pipe-chain risk classification (`adapters/cli/classifier.go`). Silently allowing on evaluator outage drops the high-risk classification results. |
| `TransportGRPC` | fail-closed | Unary RPC interceptor (`adapters/grpc/adapter.go:131-157`). Internal service surface; defaulting to fail-closed matches the rest of the control plane's default posture. |
| `TransportA2A` | fail-closed (with caveat) | A2A adapter is stub-level (see §6). If A2A is used in production at all, it should fail-closed until the adapter matures. |
| `TransportWebhook` | fail-open (with logging) | Webhook is intended for low-trust informational paths — health checks, notification dispatch, etc. Operators who use webhook for governed execution should override to fail-closed. |

The pipeline exercises this map with `p.failClosed[req.Transport]`
(`pipeline.go:190`), which is O(1) and never errors on unknown keys.

## 4. DryRun Mode Interaction

DryRun is configured via `PipelineConfig.DryRun` (`pipeline.go:23-28`). When
set, the deferred hook at `pipeline.go:118-130` applies **after** audit:

1. Pipeline runs all four stages exactly as in production mode.
2. On `return`, the deferred function fires:
   - Stopwatch is stopped (`pipeline.go:119`).
   - Audit event is published with the **real** action
     (`pipeline.go:120` → `pipeline.go:220-233`).
   - If `dryRun == true` and `decision.Action == "deny"`:
     - `decision.DryRun = true`
     - `decision.Reason = "DRY-RUN would deny: <original>"` (preserves the
       original reason under a prefix so callers can still reason about why
       the block would have fired).
     - `decision.Action = "allow"` (caller sees allow).

**Implications:**

- Audit logs in dry-run mode contain the ground-truth decision. They are the
  source of truth for "what would governance have blocked if dry-run were
  off?".
- Callers in dry-run mode see the rewritten action. Any SLO measurement that
  reads `decision.Action` from the caller side will under-count denies; any
  measurement that reads from the audit stream will count correctly.
- DryRun only rewrites `deny` → `allow`. Actions like `escalate`, `warn`,
  and `require_approval` are not touched (`pipeline.go:121`). This matches
  the semantics of "what would have blocked?" — non-terminal decisions
  would not have blocked.
- DryRun does **not** short-circuit any stage. All four stages still run, so
  dry-run has the same latency profile as production.

## 5. Fault-Injection Test Plan

One test case per DENY cell plus the parse-failure and fail-open edge cases.
"Status" column records whether the behavior is already covered by a test in
the current suite ("Existing") or is a new test to write post-YC ("New"). No
new tests are implemented by this PRD — this is a plan.

| Test ID | Fault Class | Transport | Setup | Expected | Status |
|---|---|---|---|---|---|
| FI-001 | Trust store unreachable | MCP | `mockTrustChecker` returns `err = redis down`; `req.Transport = TransportMCP`, `req.AgentID = "agent-1"` | DENY, reason contains `trust check failed`, `TrustScore == 0.0` | Existing: `TestPipeline_TrustError_FailClosed` (`governance/pipeline_test.go:109-124`) |
| FI-002 | Trust store unreachable | CLI | same as FI-001 with `Transport = TransportCLI` | DENY | New (parameterize FI-001 over all transports) |
| FI-003 | Trust store unreachable | CodeExec | same with `Transport = TransportCodeExec` | DENY | New |
| FI-004 | Trust store unreachable | gRPC | same with `Transport = TransportGRPC` | DENY | New |
| FI-005 | Trust store unreachable | A2A | same with `Transport = TransportA2A` | DENY | New |
| FI-006 | Trust store unreachable | Webhook | same with `Transport = TransportWebhook` | DENY | New |
| FI-007 | Agent ISOLATED | MCP | `mockTrustChecker.states["agent-1"] = TrustStateIsolated` | DENY, reason contains `is isolated`, `TrustScore == 0.0` | Existing: `TestPipeline_TrustDeny_Isolated` (`governance/pipeline_test.go:68-88`) |
| FI-008 | Agent TERMINATED | CLI | `mockTrustChecker.states["agent-1"] = TrustStateTerminated`, `Transport = TransportCLI` | DENY | Existing: `TestPipeline_TrustDeny_Terminated` (`governance/pipeline_test.go:90-107`) |
| FI-009 | Agent ISOLATED/TERMINATED | CodeExec | same setup as FI-007/008 with `Transport = TransportCodeExec` | DENY | New |
| FI-010 | Agent ISOLATED/TERMINATED | gRPC | same with `Transport = TransportGRPC` | DENY | New |
| FI-011 | Agent ISOLATED/TERMINATED | A2A | same with `Transport = TransportA2A` | DENY | New |
| FI-012 | Agent ISOLATED/TERMINATED | Webhook | same with `Transport = TransportWebhook` | DENY | New |
| FI-013 | MCP adapter parse failure | MCP | `adapter.ParseRequest(ctx, 42)` (unsupported raw type) | error: `unsupported raw type int for MCP adapter` | Existing: `adapters/mcp/adapter_test.go` |
| FI-014 | CLI adapter parse failure | CLI | empty `Command` field | error: `empty command` | Existing: `adapters/cli/adapter_test.go` |
| FI-015 | CodeExec adapter parse failure | CodeExec | missing `Code` or `Language` field | error: `code field is required` / `language field is required` | Existing: `adapters/codeexec/adapter_test.go` |
| FI-016 | gRPC adapter parse failure | gRPC | `CallInfo.Method == ""` | error: `Method is required`; interceptor maps to `codes.Internal` | Existing: `adapters/grpc/adapter_test.go` |
| FI-017 | A2A adapter parse failure | A2A | `TaskMessage.Action == ""` | error: `Action is required` | Existing: `adapters/a2a/adapter_test.go` |
| FI-018 | Webhook adapter parse failure | Webhook | POST `{}` to `Handler` | HTTP 400 with JSON `{"error":"..."}` | Existing: `adapters/webhook/adapter_test.go` (spot check) |
| FI-019 | Interceptor error | MCP | interceptor returns `(nil, errors.New("crashed"))` | DENY, reason contains `interceptor error` | Existing: `TestPipeline_InterceptorError` (`governance/pipeline_test.go:221-235`) |
| FI-020 | Interceptor error | CLI | same as FI-019 with `Transport = TransportCLI` | DENY | New |
| FI-021 | Interceptor error | CodeExec | same with `Transport = TransportCodeExec` | DENY | New |
| FI-022 | Interceptor error | gRPC | same with `Transport = TransportGRPC` | DENY | New |
| FI-023 | Interceptor error | A2A | same with `Transport = TransportA2A` | DENY | New |
| FI-024 | Interceptor error | Webhook | same with `Transport = TransportWebhook` | DENY | New |
| FI-025 | PolicyEval error (fail-closed) | MCP | stub evaluator returns error; `FailClosedTransports = [TransportMCP]` | DENY, reason contains `policy evaluation failed (fail-closed)` | **Blocker**: stock `*policyeval.Evaluator` never returns error on non-nil requests (noted in `governance/pipeline_coverage_test.go:167-169`). Requires a test-only evaluator interface seam before the test can be written. |
| FI-026 | PolicyEval error (fail-closed) | CLI | same as FI-025 with `FailClosedTransports = [TransportCLI]` | DENY | Same blocker as FI-025 |
| FI-027 | PolicyEval error (fail-closed) | CodeExec | same with `FailClosedTransports = [TransportCodeExec]` | DENY | Same blocker |
| FI-028 | PolicyEval error (fail-closed) | gRPC | same with `FailClosedTransports = [TransportGRPC]` | DENY | Same blocker |
| FI-029 | PolicyEval error (fail-closed) | A2A | same with `FailClosedTransports = [TransportA2A]` | DENY | Same blocker |
| FI-030 | PolicyEval error (fail-closed) | Webhook | same with `FailClosedTransports = [TransportWebhook]` | DENY | Same blocker |
| FI-031 | PolicyEval error (fail-open) | any | stub evaluator returns error; transport NOT in `FailClosedTransports` | ALLOW (pre-existing default), no reason overwrite | Same blocker as FI-025 |
| FI-032 | `FailClosedTransports` map construction | n/a | `PipelineConfig{FailClosedTransports: [MCP, CodeExec]}` | `p.failClosed[MCP] && p.failClosed[CodeExec] && !p.failClosed[CLI]` | Existing: `TestPipeline_FailClosedTransports_BuildsMap` (`governance/pipeline_coverage_test.go:164-192`) |
| FI-033 | Downstream tool 5xx | any | allow decision, then downstream returns 500 | governance `decision.Action == "allow"` emitted; 5xx bubbles to caller unchanged | New (integration test; pipeline is not in the 5xx path) |
| FI-034 | DryRun rewrite preserves audit | any | `DryRun = true`; force a deny (blocked trust state); capture auditor events | audit event contains `action == "deny"`; caller sees `action == "allow"`, `DryRun == true`, `Reason` starts with `DRY-RUN would deny:` | New (no dedicated test today; `TestPipeline_AuditEventEmitted` at `governance/pipeline_test.go:237-269` exercises audit emission but not the dry-run branch) |

**Blocker note (FI-025 / FI-031):** the pipeline's fail-closed-vs-fail-open
branch at `governance/pipeline.go:189-195` is currently unreachable through
the public `*policyeval.Evaluator` type, because that evaluator does not
return an error for non-nil requests. Closing FI-025 through FI-031 requires
one of:

1. A test-only evaluator interface (extract the method signature into an
   interface the pipeline depends on, and inject a faulting stub in tests).
2. A genuine failure mode in `*policyeval.Evaluator` (e.g., database-backed
   policy fetch) that the pipeline can actually encounter.

Either is a code change, not documentation. Logged here rather than acted on.

## 6. Known Gaps and Recommendations

- **A2A adapter is stub-level.** `adapters/a2a/adapter.go:1-6` declares the
  protocol "still evolving"; `ForwardGoverned`, `InspectResponse`, and
  `EmitGovernanceMetadata` are all no-ops (`:89-102`). The adapter parses
  task messages into `GovernanceRequest` with a minimal local schema; it
  does not integrate with Google A2A's actual wire protocol. Fail behavior
  in the matrix above is nominal (what the stub does), not
  production-tested. Treat A2A cells as "intended behavior" until the
  adapter matures.

- **Adapter-level parse failure is not uniformly surfaced.** The matrix shows
  three distinct behaviors: HTTP 400 (webhook), `codes.Internal` (gRPC via
  the provided interceptor), and "error returned to caller" for MCP/CLI/
  CodeExec/A2A. The last group depends on the embedding runtime to map the
  error to a protocol response. If a runtime silently drops the error, the
  request could fail open at the runtime layer even though the GIL behavior
  is correct. Recommendation: add `ErrorHandler` hooks or a shared
  "adapter-error-to-decision" helper so every runtime emits an audit event
  and a deterministic caller-visible response on parse failure.

- **`FailClosedTransports` default is empty.** `pipeline.go:19-21` ships with
  `nil`, meaning PolicyEval errors are silently allowed on every transport
  until operators opt in. The defaults recommended in §3 should become the
  shipped default in a subsequent PR. This is a one-line config change but
  is out of scope for this documentation PRD.

- **PolicyEval error path is currently unreachable through the public
  evaluator.** See the FI-025–FI-031 blocker note in §5. This means the
  fail-closed-vs-fail-open branch is deliberate and readable but not
  behaviorally covered by tests. Prioritize a test-only evaluator seam so
  the behavior can be verified end-to-end.

- **DryRun is under-tested.** The rewrite logic at
  `governance/pipeline.go:121-129` has no dedicated test today.
  `TestPipeline_AuditEventEmitted` (`governance/pipeline_test.go:237-269`)
  exercises audit emission but not the dry-run action rewrite. FI-034
  covers this gap.

---

*Authored April 17, 2026 per PRD-004 "Transport Fail-Mode Matrix".
Document is an audit of existing behavior in the `main` branch of the GIL
repo at the time of writing. Line citations refer to the present snapshot;
future refactors must update this document alongside the code change.*
