"""The agent loop and the ONLY place the OPA gate is enforced. See CLAUDE.md:
there must be no code path where gating is optional, skippable, or model-decided.

Qwen drives a function-calling loop over enrich_epss / check_kev / propose_bump,
but whatever it does or doesn't call, this module always assembles the policy
input from the tools' real (network/deterministic) outputs -- never from the
model's own text -- and always runs `opa eval` before printing a verdict.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent.tools import check_kev, enrich_epss, propose_bump
from cloud.alibaba import qwen_complete

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = REPO_ROOT / "policy"
MAX_TOOL_TURNS = 4

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "enrich_epss",
            "description": "Look up the EPSS exploitation-probability score for a CVE.",
            "parameters": {
                "type": "object",
                "properties": {"cve": {"type": "string"}},
                "required": ["cve"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_kev",
            "description": "Check whether a CVE is in CISA's Known Exploited Vulnerabilities catalog.",
            "parameters": {
                "type": "object",
                "properties": {"cve": {"type": "string"}},
                "required": ["cve"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_bump",
            "description": "Propose bumping a package from its installed version to its fixed version.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pkg": {"type": "string"},
                    "installed_version": {"type": "string"},
                    "fixed_version": {"type": "string"},
                },
                "required": ["pkg", "installed_version", "fixed_version"],
            },
        },
    },
]

TOOL_IMPLS = {
    "enrich_epss": lambda args: enrich_epss(args["cve"]),
    "check_kev": lambda args: check_kev(args["cve"]),
    "propose_bump": lambda args: propose_bump(
        args["pkg"], args["installed_version"], args["fixed_version"]
    ),
}


def load_first_finding(trivy_path: Path) -> dict[str, Any]:
    report = json.loads(trivy_path.read_text())
    vuln = report["Results"][0]["Vulnerabilities"][0]
    return {
        "cve": vuln["VulnerabilityID"],
        "package": vuln["PkgName"],
        "installed_version": vuln["InstalledVersion"],
        "fixed_version": vuln["FixedVersion"],
    }


def run_agent_loop(finding: dict[str, Any]) -> dict[str, Any]:
    """Let Qwen call enrich_epss / check_kev / propose_bump for this finding.

    Returns whatever real tool outputs were collected, keyed by tool name.
    """
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You are a CVE remediation agent. For the given finding, call "
                "enrich_epss and check_kev with its CVE ID, then call "
                "propose_bump with its package and versions. Call each tool "
                "exactly once, then stop."
            ),
        },
        {"role": "user", "content": json.dumps(finding)},
    ]

    collected: dict[str, Any] = {}
    for _ in range(MAX_TOOL_TURNS):
        message = qwen_complete(messages, tools=TOOLS)
        tool_calls = getattr(message, "tool_calls", None)
        if not tool_calls:
            break

        messages.append(
            {
                "role": "assistant",
                "content": message.content,
                "tool_calls": [tc.model_dump() for tc in tool_calls],
            }
        )
        for tool_call in tool_calls:
            name = tool_call.function.name
            args = json.loads(tool_call.function.arguments)
            result = TOOL_IMPLS[name](args)
            collected[name] = result
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result),
                }
            )

    return collected


def build_policy_input(finding: dict[str, Any], collected: dict[str, Any]) -> dict[str, Any]:
    """Assemble the OPA input from real tool outputs, calling any tool the
    model skipped directly. The gate's inputs are never trusted from the
    model's own summary -- only from actual tool execution.
    """
    epss = collected.get("enrich_epss")
    if epss is None:
        epss = enrich_epss(finding["cve"])

    in_kev = collected.get("check_kev")
    if in_kev is None:
        in_kev = check_kev(finding["cve"])

    bump = collected.get("propose_bump")
    if bump is None:
        bump = propose_bump(
            finding["package"], finding["installed_version"], finding["fixed_version"]
        )

    return {
        "cve": finding["cve"],
        "package": finding["package"],
        "epss": epss,
        "in_kev": in_kev,
        "bump": bump,
    }


def opa_eval_verdict(policy_input: dict[str, Any]) -> str:
    """Deterministically evaluate data.ci.v1.remediation via the opa binary.

    This is the non-negotiable gate: it always runs, regardless of what the
    agent loop above did, and the model has no path to bypass or influence it.
    """
    result = subprocess.run(
        [
            "opa",
            "eval",
            "-d",
            str(POLICY_DIR),
            "-i",
            "/dev/stdin",
            "--format",
            "json",
            "data.ci.v1.remediation",
        ],
        input=json.dumps(policy_input),
        capture_output=True,
        text=True,
        check=True,
    )
    parsed = json.loads(result.stdout)
    return parsed["result"][0]["expressions"][0]["value"]


def main() -> None:
    trivy_path = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "fixtures" / "sample-trivy.json"

    finding = load_first_finding(trivy_path)
    collected = run_agent_loop(finding)
    policy_input = build_policy_input(finding, collected)
    verdict = opa_eval_verdict(policy_input)

    print(json.dumps(policy_input, indent=2))
    print(f"\nverdict: {verdict}")


if __name__ == "__main__":
    main()
