"""Assert each policy_inputs/*.json fixture yields its expected verdict via `opa eval`.

Run: python -m fixtures.run_policy_tests
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = REPO_ROOT / "policy"
INPUTS_DIR = REPO_ROOT / "fixtures" / "policy_inputs"

# fixture filename (without .json) -> expected data.ci.v1.remediation verdict
EXPECTED = {
    "auto": "auto",
    "human": "human",
    "reject": "reject",
}


def eval_verdict(input_path: Path) -> str:
    result = subprocess.run(
        [
            "opa",
            "eval",
            "-d",
            str(POLICY_DIR),
            "-i",
            str(input_path),
            "--format",
            "json",
            "data.ci.v1.remediation",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    parsed = json.loads(result.stdout)
    return parsed["result"][0]["expressions"][0]["value"]


def main() -> int:
    failures = []
    for name, expected in EXPECTED.items():
        input_path = INPUTS_DIR / f"{name}.json"
        actual = eval_verdict(input_path)
        status = "PASS" if actual == expected else "FAIL"
        print(f"[{status}] {name}: expected={expected} actual={actual}")
        if actual != expected:
            failures.append(name)

    if failures:
        print(f"\n{len(failures)} fixture(s) failed: {failures}")
        return 1
    print("\nAll policy fixtures passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
