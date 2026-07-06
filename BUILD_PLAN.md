# KEVlar — Build Plan
### Qwen Cloud Hackathon · Track 4 (Autopilot Agent) · Solo · Deadline 10 Jul 02:30 IST

> Working name: **KEVlar** — armor for your dependencies, driven by what's *actually being exploited*. Rename freely; it just needs to be consistent across repo, README, and video.

---

## 1. The USP (memorize this — it goes in the video, README, and Devpost text)

> An autonomous remediation agent that only acts on what's **provably being exploited** — and a **policy engine, not the AI**, decides whether it's allowed to act.

Two legs:
1. **Exploitability over severity.** EPSS probability + CISA KEV drive priority and autonomy level. A KEV-listed, high-EPSS CVE gets fast-tracked; a CVSS 9.8 nobody exploits gets deprioritized.
2. **Governed autonomy / separation of duties.** The model *proposes*; OPA *disposes*. The LLM never holds merge authority. Risk appetite lives in versioned, testable Rego.

Bonus leg for the "Impact" score: every decision writes an **audit-grade evidence bundle** (Rego input + verdict, EPSS/KEV proof, diff, CI result) to OSS.

---

## 2. Locked technical decisions (do not re-debate during the build)

| Concern | Decision | Why |
|---|---|---|
| Language | Python 3.11 | Reuses your prior CVE engine + DefectDojo/Trivy tooling |
| Reasoning | Qwen via DashScope, OpenAI-compatible endpoint | Simplest integration; pull exact base_url + model id from your Model Studio console (don't hardcode a stale URL). Use the strongest reasoning model available (qwen-max class) for planning. |
| Agent loop | Model-driven **function calling** | Genuine agent: model calls tools to enrich, propose, then orchestrator gates |
| Gate enforcement | OPA enforced by the **orchestrator**, post-proposal, **non-bypassable** | The model must never be able to skip the gate — that's the whole USP |
| OPA runtime | `opa eval` binary, bundled in the container, no network | Deterministic, serverless-friendly, scale-to-zero safe |
| Scanner input | Trivy JSON (a committed sample report) | No live scanning infra needed for the demo |
| Exploitability | EPSS API (`api.first.org/data/v1/epss`) + CISA KEV JSON feed | Free, no keys |
| Execution | GitHub PR via REST/PyGithub (branch → commit bump → open PR) | The PR is the human-facing surface |
| MCP | Thin MCP server wrapping the **same** git tool handlers | Real, demoable MCP integration; runtime path stays function-calling. **First thing to cut if behind.** |
| Persistence | Evidence bundles as JSON in **OSS** | $0, no standing DB; metrics computed by reading OSS |
| Frontend | Static HTML digest rendered to OSS + the GitHub PR | Self-contained, nothing to host separately |
| Compute | **Function Compute** custom-container (scale-to-zero), HTTP-triggered | Bundles the opa binary + deps; credits last far longer than a standing ACK cluster |
| Alibaba isolation | All DashScope + OSS calls live in `cloud/alibaba.py` | **This single file is your deployment-proof artifact** |

---

## 3. Architecture (the part judges should "get" in 30 seconds)

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
        │                   │                     │
   open PR + merge     open PR (no merge)     log only
        └─────────┬─────────┘                     │
                  ▼                               ▼
        evidence bundle → OSS  ◀───────────  audit log → OSS
                  │
                  ▼
        HTML digest → OSS  (the "frontend")
```

Key sentence for the README: *"The reasoning model proposes a remediation; a deterministic policy engine independently adjudicates it; the model never has unilateral merge authority."*

---

## 4. Repo layout

```
kevlar/
  agent/
    orchestrator.py     # the loop; ENFORCES the OPA gate
    qwen_client.py      # DashScope wrapper
    tools.py            # enrich_epss, check_kev, propose_bump, open_pr
  policy/
    remediation.rego    # the USP policy
    data.json           # allowlist + thresholds
  cloud/
    alibaba.py          # DashScope + OSS  ← DEPLOYMENT-PROOF FILE
  mcp/
    git_server.py       # MCP wrapper over git tools (stretch)
  digest/
    render.py           # OSS HTML report
  fixtures/
    sample-trivy.json
    policy_inputs/*.json
  fc/
    Dockerfile          # bundles opa binary + python deps
    s.yaml              # Serverless Devs config
  README.md
  LICENSE               # MUST be visible in the repo About section
  CLAUDE.md
```

---

## 5. `CLAUDE.md` (drop this in the repo root before day 1)

```md
# KEVlar — agent rules

- One concern per change. Commit after each green step. /clear between concerns.
- The OPA gate is enforced by the orchestrator, NEVER by the model.
  Never add a code path where gating is optional or model-decided.
- All Alibaba Cloud calls (DashScope, OSS) live ONLY in cloud/alibaba.py.
- Policy evaluation is deterministic: `opa eval`, no network, no LLM.
- Secrets via env vars (KMS-backed in Function Compute). Never commit tokens.
- Tests/fixtures go in fixtures/ (not tests/).
- Python 3.11, full type hints, ruff clean.
- Prefer small, readable functions over cleverness. This is a security tool;
  auditability beats brevity.
```

---

## 6. BLOCKING actions — do today, before anything else

- [ ] **Confirm the reuse rule.** Can you reuse your prior Qwen CVE pipeline + EPSS/KEV code? Plan below assumes yes. If no, days 2–3 roughly double — tell me and we re-scope immediately.
- [ ] **Request Alibaba credits** via the hackathon coupon form. Can take a day+ to land.
- [ ] **Set a billing alarm** so a runaway loop can't drain credits.
- [ ] Create the repo, add `LICENSE` (MIT/Apache-2.0) and `CLAUDE.md`. License must be detectable in the About section.

---

## 7. Day-by-day (one concern each, ~1–2 hrs with Sonnet doing the code)

Each day: paste the **brief** into Claude Code, work it to the acceptance criteria, commit.

### Jul 1 — Platform hello-world
**Brief:** "Set up `cloud/alibaba.py` with a `qwen_complete(messages, tools=None)` function using the DashScope OpenAI-compatible endpoint (base_url and model id from env vars). Add a `smoke_test.py` that sends one prompt and prints the response."
**Acceptance:** One real Qwen response prints, sourced from DashScope. Credits confirmed landed.

### Jul 2 — Core spine, local
**Brief:** "Build the minimal pipeline: load `fixtures/sample-trivy.json`, extract one finding (cve, package, installed, fixed version). Add `agent/tools.py:propose_bump()` returning a semver bump proposal. Add `policy/remediation.rego` with a placeholder rule and wire `agent/orchestrator.py` to call `opa eval` on the proposal and print the verdict. Reuse my prior CVE-engine parsing where it fits."
**Acceptance:** `python -m agent.orchestrator` prints a verdict for one CVE. No cloud yet.

### Jul 3 — MOAT DAY (protect this one)
**Brief:** "Add `enrich_epss(cve)` (api.first.org EPSS) and `check_kev(cve)` (CISA KEV JSON, cached). Rewrite `policy/remediation.rego` so the verdict is exploitability-driven:
- `auto` if (in_kev OR epss > 0.5) AND bump is non-major AND package in allowlist
- `human` if exploitable but bump is major OR not allowlisted
- `reject` otherwise
Thresholds + allowlist in `policy/data.json`. Add 4 fixture inputs in `fixtures/policy_inputs/` covering each branch and a test runner that asserts the expected verdict."
**Acceptance:** Four policy fixtures pass. The Rego is the moat — clean, commented, reviewable.

### Jul 4 — Tools as agent + MCP wrapper
**Brief:** "Convert enrich_epss / check_kev / propose_bump / open_pr into Qwen function-calling tools and drive `orchestrator.py` as a real agent loop: model decides which tools to call, THEN the orchestrator deterministically calls OPA on the final proposal (model cannot skip it). Add `open_pr()` using GitHub REST (branch → commit bumped manifest → open PR). Then wrap the git tools as a minimal MCP server in `mcp/git_server.py`."
**Acceptance:** Agent opens a real PR on a test repo. MCP server lists/calls the git tool. *(If short on time: ship function-calling, defer the MCP server.)*

### Jul 5 — Deploy to Alibaba (the eligibility gate — do NOT slip)
**Brief:** "Write `fc/Dockerfile` bundling the `opa` binary + Python deps. Add an HTTP handler entrypoint. Add `fc/s.yaml` for Serverless Devs. Deploy to Function Compute. Wire OSS read/write into `cloud/alibaba.py` (oss2). Confirm the whole pipeline runs end-to-end in the cloud."
**Acceptance:** A single HTTP call to the deployed function ingests a finding and returns a verdict, running on Alibaba. `cloud/alibaba.py` clearly shows DashScope + OSS usage — **this is your deployment-proof file.**

### Jul 6 — Evidence bundle + metrics
**Brief:** "On every run, write an evidence bundle JSON to OSS (`runs/{ts}-{cve}.json`: input, EPSS/KEV proof, Rego verdict, diff, PR url). Seed ~30 findings, run them, then compute metrics by reading OSS: total ingested, auto-remediated %, MTTR (synthetic detection→PR), reject count. Output one chart (matplotlib PNG → OSS)."
**Acceptance:** One chart exists showing the efficiency story. Bundles in OSS.

### Jul 7 — Diagrams + README
**Brief:** "Render the HTML digest (`digest/render.py` → OSS) summarizing a run. Write the README like internal docs: USP, architecture, how the gate works, how to run, Alibaba services used. Confirm LICENSE visible in About."
**Acceptance:** README reads as credible production docs. (Ping me — I'll generate the architecture + deployment diagrams.)

### Jul 8 — The 3-minute video
**Brief (script below):** record + upload **public** to YouTube. This is where solo entries are won or lost.
**Acceptance:** Public link, under ~3 min, opens on the money shot.

### Jul 9 — Submit (hours early)
- [ ] Devpost form; identify **Track 4**.
- [ ] Public repo + visible license.
- [ ] Architecture diagram attached.
- [ ] Deployment-proof: link to `cloud/alibaba.py` + short recording.
- [ ] Demo video link.
- [ ] Text description (lead with the USP one-liner).
- [ ] Optional: blog post → extra prize eligibility.
- [ ] **Submit by Jul 9 evening. Never the 2am cutoff.**

---

## 8. Video script (the make-or-break asset)

**0:00–0:30 — Hook (the money shot).** "This CVE is being actively exploited in the wild right now." Show KEV/EPSS evidence → agent proposes the bump → OPA returns `auto` → PR opens and merges. "Detection to merged fix: 11 minutes."

**0:30–1:15 — The differentiator.** "But it doesn't blindly auto-fix." Show a major-version bump on the same severity → OPA returns `human` → PR opened but held for sign-off. "The model proposes. A policy engine — not the AI — decides. The agent never has unilateral merge authority."

**1:15–2:15 — How.** 20-second architecture pan. Show the Rego (exploitability rule), the EPSS/KEV enrichment, the evidence bundle in OSS, running on Function Compute.

**2:15–3:00 — Impact.** The metrics chart. "47 CVEs, 38 auto-remediated, MTTR days → minutes, every decision auditable." Close on the USP line.

---

## 9. Risk register

| Risk | Mitigation |
|---|---|
| Reuse barred → scope doubles | Confirm rule **today**; re-scope before day 2 |
| Credits land late | Request today; days 1–4 are local/cloud-agnostic so you're not blocked |
| Deploy backloaded → eligibility miss | Deploy is **day 5**, not day 8 — protected slack |
| OPA in serverless awkward | `opa eval` binary in the container; no standing server |
| MCP eats the budget | It's a wrapper over existing handlers; cut to function-calling if behind |
| Solo portal panic at 2am | Submit day 9 evening |

## 10. Cut list (if you fall behind, drop in this order)
1. MCP server (keep function-calling).
2. HTML digest (PR + chart is enough).
3. Second demo CVE (one clean auto + one clean human-review is enough).
4. Live GitHub PR (show a pre-opened PR in the video).

**Never cut:** the exploitability Rego, the Alibaba deployment, the video hook, the eligibility checklist.
