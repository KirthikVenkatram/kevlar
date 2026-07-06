# CLAUDE.md — KEVlar

Exploitability-driven, policy-gated autonomous CVE remediation agent.
The reasoning model **proposes** a remediation; a deterministic policy engine
**adjudicates** it; the model never has unilateral merge authority.

Read `BUILD_PLAN.md` for scope and the day-by-day plan.

## Non-negotiable invariants
- The OPA gate is enforced by `agent/orchestrator.py`, **never by the model**.
  There must be no code path where gating is optional, skippable, or model-decided.
  This is the entire point of the project — treat any change that weakens it as a bug.
- Policy evaluation is deterministic: `opa eval` on committed Rego + `policy/data.json`.
  No network, no LLM, no randomness inside the gate.
- All Alibaba Cloud calls (DashScope, OSS) live **only** in `cloud/alibaba.py`.
  This file is the deployment-proof artifact; keep it self-contained and legible.
- Secrets come from env vars (KMS-backed in Function Compute). Never commit tokens,
  keys, or `.env`.

## Workflow
- One concern per change. Get it green, commit, then `/clear` before the next concern.
- Prefer small, readable functions over cleverness. This is a security tool —
  auditability beats brevity.
- Don't add dependencies without a reason; keep `requirements.txt` minimal.

## Conventions
- Python 3.11, full type hints, `ruff` clean.
- Tests and fixtures go in `fixtures/` (not `tests/`).
- Commits: `type(scope): summary` — types: feat, fix, chore, docs, refactor, test.
  e.g. `feat(policy): exploitability-driven remediation verdict`.

## Commands
- Run pipeline locally:  `python -m agent.orchestrator fixtures/sample-trivy.json`
- Evaluate policy:        `opa eval -d policy/ -i <input.json> 'data.ci.v1.remediation'`
- Policy fixtures:        `python -m fixtures.run_policy_tests`
- Smoke-test Qwen:        `python smoke_test.py`
- Lint:                   `ruff check .`

## Definition of done (per concern)
- Acceptance criterion in `BUILD_PLAN.md` met.
- `ruff` clean, relevant fixtures pass.
- No secrets in the diff. Gate invariant intact.
- Committed with a conventional-commit message.