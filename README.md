# KEVlar

Armor for your dependencies, driven by what's *actually being exploited*.

An autonomous CVE remediation agent that only acts on what's **provably being
exploited** — and a **policy engine, not the AI**, decides whether it's
allowed to act.

## USP

Two legs:

1. **Exploitability over severity.** EPSS probability + CISA KEV drive
   priority and autonomy level. A KEV-listed, high-EPSS CVE gets
   fast-tracked; a CVSS 9.8 nobody exploits gets deprioritized.
2. **Governed autonomy / separation of duties.** The reasoning model
   *proposes* a remediation; a deterministic policy engine *adjudicates* it.
   The model never has unilateral merge authority. Risk appetite lives in
   versioned, testable Rego.

## Architecture

```
Trivy report  ──▶  Qwen agent (function-calling loop)
                     ├─ enrich_epss(cve)
                     ├─ check_kev(cve)
                     └─ propose_bump(pkg, fixed_version)
                            │
                            ▼  proposal handed to orchestrator
                   ┌──────────────────────────────┐
                   │ OPA gate  (opa eval)          │  ← enforced here, model can't skip
                   │ data.ci.v1.remediation        │
                   └──────────────────────────────┘
                            │ verdict
        ┌───────────────────┼───────────────────┐
   auto-approve         human-review           reject
```

The reasoning model proposes a remediation; a deterministic policy engine
independently adjudicates it; the model never has unilateral merge authority.

`agent/orchestrator.py` is the only place the gate is enforced. Whatever the
Qwen tool-calling loop does or doesn't do, the orchestrator assembles the
policy input from the tools' real outputs (never the model's own text) and
always runs `opa eval` before a verdict exists. There is no code path where
gating is optional, skippable, or model-decided.

## The gate

`policy/remediation.rego` (`data.ci.v1.remediation`) returns:

- **`auto`** — exploitable (KEV-listed or EPSS > threshold), a non-major
  version bump, and the package is allowlisted.
- **`human`** — exploitable, but the bump is major or the package isn't
  allowlisted.
- **`reject`** — not exploitable.

Thresholds and the allowlist live in `policy/data.json`, versioned and
testable independently of any model.

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# needs opa on PATH: https://www.openpolicyagent.org/docs/latest/#running-opa
export DASHSCOPE_API_KEY=...        # from Alibaba Model Studio
export DASHSCOPE_BASE_URL=...       # optional, defaults to the public endpoint
export DASHSCOPE_MODEL=qwen-max     # optional, this is the default

python smoke_test.py                          # one Qwen round-trip
python -m agent.orchestrator fixtures/sample-trivy.json  # full pipeline, prints a verdict
```

## Evaluating the policy

```bash
opa eval -d policy/ -i <input.json> 'data.ci.v1.remediation'
python -m fixtures.run_policy_tests   # asserts all 3 fixtures (auto/human/reject)
```

## Deployment

Stub — Alibaba Function Compute deployment (bundling the `opa` binary,
wiring OSS for evidence bundles) lands in a later session. All Alibaba Cloud
calls live in `cloud/alibaba.py`, the deployment-proof artifact.
