# Contributing to GIL

Thank you for considering a contribution. GIL is a small, focused library,
and that's intentional — scope changes are welcome but need a concrete use
case attached.

## This project is maintained by a solo developer

Security issues get priority. Response times on other issues may vary. If a
PR sits idle for more than a few weeks, a polite bump is fine.

## Filing issues

Use the templates. They are not red tape; they collect the information that
is needed to diagnose every report.

- **Bug reports**: Go version, OS, steps to reproduce, expected vs actual.
  A minimal reproducer that compiles is worth ten paragraphs of description.
- **Feature requests**: the use case, the proposed solution, alternatives
  considered. Features without a concrete use case will likely be closed
  as "won't fix" — not because the idea is bad, but because scope discipline
  is how a small library stays maintainable.
- **Questions**: fine to open as issues. Mark them with the `question` label.

## Submitting pull requests

1. Fork the repository.
2. Create a branch from `main`. Name it for the change: `fix-trust-nil-panic`,
   `add-grpc-adapter`, etc.
3. Make the change. Keep commits focused.
4. Ensure the following pass locally:
   ```
   gofmt -l .        # prints nothing
   go vet ./...      # clean
   go test ./... -race -count=1   # all pass, no races
   golangci-lint run ./...         # clean (CI runs this too)
   ```
5. Open a PR against `main`. Describe what changed and why. Link the issue
   if one exists.
6. CI will run on Go 1.22 and 1.23. A green CI is required for review.

For larger changes — new adapters, new extension points, changes to
`governance/` — open an issue first to discuss the shape before writing code.
That saves both sides a round-trip.

## Code style

- `gofmt` is the style guide. Run `gofmt -w .` before committing.
- `golangci-lint` enforces a small set of additional rules. CI runs it; you
  can too with the config check out of the box.
- Prefer small, focused functions. The existing code is a reasonable
  reference.
- Tests live next to the code they test. Table-driven tests are preferred
  where they fit.
- Public identifiers need doc comments. A good doc comment says *what
  contract the reader can rely on*, not what the code does.

## Test requirements

All PRs must keep the following green:

- `go test ./... -race -count=1` — unit and integration tests pass with
  the race detector on, no caching.
- Coverage must not drop on the packages you touched. If you add new
  public behaviour, it needs a test that exercises it.

The existing coverage floors are:
- `governance/` ≥ 90%
- `policyeval/` ≥ 88%
- `adapters/cli/` ≥ 93%
- `adapters/codeexec/` ≥ 98%
- `adapters/mcp/` ≥ 86%

## Scope: what belongs here vs elsewhere

GIL is deliberately a **decision layer**, not an intelligence layer. The
following belongs in GIL:

- Pipeline stages and their contracts.
- Transport adapters for widely-used protocols (MCP, CLI, code-exec).
- Portable policy evaluation primitives that do not require I/O.
- Interfaces for pluggable trust and audit backends.

The following does **not** belong in GIL and will be declined:

- LLM-based intent evaluation (the Semantic Judge in the commercial Fulcrum
  platform handles this).
- Persistent trust state, Beta-distribution scoring, or anomaly detection
  (Fulcrum's trust subsystem — `fulcrum-trust` on PyPI).
- Cost modelling, budget enforcement, billing.
- Multi-tenant infrastructure concerns (migrations, RLS, dashboards).
- Formal verification of policy invariants (lives in the commercial
  Fulcrum repo alongside the Lean 4 proofs).

A new transport adapter, a new interceptor helper, a performance fix, a
bug report with a failing test — these are in scope.

## Licensing

By submitting a pull request, you agree that your contribution is licensed
under the Apache License 2.0 (the same license as the repository). No CLA
is required.

## Security issues

**Do not open a public issue for security vulnerabilities.** Follow the
process in [SECURITY.md](./SECURITY.md).
