# Security Policy

## Reporting a vulnerability

Email: **security@fulcrumlayer.io**

Please include:

- A description of the issue and the version or commit affected.
- A minimal reproducer if possible.
- Your assessment of impact and any known exploitation conditions.
- Whether the issue has been disclosed elsewhere.

You will get an acknowledgement within a few business days. We ask for a
**90-day responsible-disclosure window** from first report; coordinated
public disclosure can happen sooner if a fix ships earlier, or later by
mutual agreement if the issue is complex.

Do **not** file public GitHub issues for security vulnerabilities.

## What is in scope

GIL is the enforcement path for tool calls. The following are in scope:

- Bypasses of the pipeline stages (a tool call reaching a downstream tool
  without passing through `Pipeline.Evaluate`).
- Incorrect fail-closed / fail-open behaviour (e.g. an evaluator error on
  a fail-closed transport that leads to allow).
- Race conditions in the pipeline or any adapter.
- Logic bugs in the static policy or interceptor stages that invert
  intended semantics.
- Vulnerabilities in parser code across the adapters (`adapters/cli/parser.go`,
  the code-exec analyzers, `adapters/mcp/adapter.go`).

## Known limitations

GIL evaluates **tool call metadata and arguments**. It does not perform
semantic analysis of tool outputs, free-form natural language, or complex
code semantics. Some adversarial inputs are by design out of scope for the
open-source enforcement layer:

- **WASM bytecode payloads.** The code-exec adapter recognises Python and
  JavaScript source; WebAssembly is not analysed.
- **Steganographic payloads.** Arguments that encode intent in formats the
  adapters do not parse (base64-wrapped compiled binaries, image payloads,
  multi-encoded strings) will pass inspection unless an interceptor catches
  them.
- **AST-aware polymorphism.** The code-exec analyzers handle a set of known
  obfuscation patterns (see `adapters/codeexec/analyzer_*.go`). Novel
  transformations that rewrite the AST while preserving behaviour may evade
  them.

These are tracked as **P2-04** on Fulcrum's roadmap. Mitigations for them
live in the commercial platform's Semantic Judge, which performs LLM-based
intent evaluation on the full request — intentionally outside the enforcement
layer because that work is too expensive and too dependent on moving models
to ship as a static library.

## What GIL is not

GIL enforces governance decisions. It does not make them intelligent. For
LLM-based intent evaluation, semantic output inspection, and Bayesian trust
scoring, see the full [Fulcrum](https://fulcrumlayer.io) platform. If the
right answer to your issue is "the enforcement layer let this through
because it has no semantic understanding," the fix is almost certainly in
a different repository.

## Dependencies

GIL's root module depends only on:

- `github.com/google/uuid`
- `github.com/stretchr/testify` (test-only)

Transitive dependencies are intentionally minimised. `govulncheck` is run on
every push and pull request via the `security` job in `.github/workflows/ci.yml`
(Go 1.26 toolchain) and is expected to report zero vulnerabilities in the
production dependency set.

## Disclosure credit

Unless you ask otherwise, valid reports are credited in the release notes
of the fix.
