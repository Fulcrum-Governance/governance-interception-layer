# Changelog

All notable changes to the **Governance Interception Layer (GIL)** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `DecisionMode` type with four epistemic levels (`proved` / `deterministic` / `classified` / `human-approved`) attached to every `GovernanceDecision` and `AuditEvent`. Captures **how** a decision was reached, not just the outcome — every governance decision now carries a named mode rather than the generic "governed" label. ([4b2d5eb], [a5a724b], [9d406cb])
- `ParseError` typed error for uniform adapter failure semantics across MCP, CLI, and code-execution transports. Replaces ad-hoc string errors with a single shared type so downstream callers can branch on parse-vs-evaluate failure. ([1f15ae7])
- DryRun test coverage for deny-to-allow rewrite and audit emission paths. ([8a49a30])
- DecisionMode coverage at every pipeline decision point in tests. ([7468439])

### Changed
- `PolicyEvaluator` interface extracted as a named seam (PRD-004R) with explicit error-path tests. Makes the policy-eval boundary swappable and testable independently of the rest of the pipeline. ([2fb0519])
- README narrative aligned to the governance-kernel framing — replaces earlier platform / cognitive-platform language. ([b03d7c5])

### Fixed
- Three bugs surfaced by an external GStack audit (post-v0.1.0 hardening pass). ([caf5f8a])
- Pipeline now defaults security-critical transports (MCP, code-execution) to fail-closed when policy evaluation errors. Previous behavior allowed for ambiguous fail-open scenarios on transient evaluator errors. ([0314824])

### Documentation
- Transport fail-mode matrix added at `docs/security/FAIL_MODE_MATRIX.md`. ([67f56f2])
- `DecisionMode` semantics noted in the fail-mode matrix. ([eb68ac5])

## [0.1.0] — 2026-04-15

Initial public release of the Governance Interception Layer.

### Added
- Protocol-agnostic pre-execution enforcement for AI agent tool calls.
- 4-stage governance pipeline: **trust → static policy → domain interceptor → portable policy evaluator**.
- Transport adapters:
  - **MCP** (JSON-RPC interception)
  - **CLI** (dispatch governance)
  - **Code execution** (Python and JavaScript obfuscation pattern detection)
- Apache 2.0 license; designed as the open-source enforcement core of [Fulcrum](https://fulcrumlayer.io).
- Initial release commit: [ef9f373].

---

[ef9f373]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/ef9f373
[caf5f8a]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/caf5f8a
[b03d7c5]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/b03d7c5
[67f56f2]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/67f56f2
[0314824]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/0314824
[2fb0519]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/2fb0519
[8a49a30]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/8a49a30
[1f15ae7]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/1f15ae7
[4b2d5eb]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/4b2d5eb
[a5a724b]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/a5a724b
[9d406cb]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/9d406cb
[7468439]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/7468439
[eb68ac5]: https://github.com/Fulcrum-Governance/governance-interception-layer/commit/eb68ac5
