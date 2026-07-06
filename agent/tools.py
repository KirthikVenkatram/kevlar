"""Agent tools: enrichment + remediation proposal. No network in policy/orchestrator —
these are the only functions in the pipeline that call out to the network, and only
to public, keyless feeds (EPSS, CISA KEV).
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_CACHE_PATH = Path(os.environ.get("KEV_CACHE_PATH", ".cache/kev-feed.json"))
KEV_CACHE_TTL_SECONDS = 24 * 60 * 60


def enrich_epss(cve: str) -> float:
    """Return the EPSS exploitation-probability score for a CVE (0.0 if unknown)."""
    response = requests.get(EPSS_URL, params={"cve": cve}, timeout=10)
    response.raise_for_status()
    data = response.json().get("data", [])
    if not data:
        return 0.0
    return float(data[0]["epss"])


def _load_kev_feed() -> dict[str, Any]:
    if KEV_CACHE_PATH.exists():
        age = time.time() - KEV_CACHE_PATH.stat().st_mtime
        if age < KEV_CACHE_TTL_SECONDS:
            return json.loads(KEV_CACHE_PATH.read_text())

    response = requests.get(KEV_URL, timeout=10)
    response.raise_for_status()
    feed = response.json()

    KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEV_CACHE_PATH.write_text(json.dumps(feed))
    return feed


def check_kev(cve: str) -> bool:
    """Return True if the CVE is in CISA's Known Exploited Vulnerabilities catalog."""
    feed = _load_kev_feed()
    return any(v["cveID"] == cve for v in feed.get("vulnerabilities", []))


def _major_version(version: str) -> str:
    match = re.match(r"\d+", version)
    return match.group(0) if match else version


def propose_bump(pkg: str, installed_version: str, fixed_version: str) -> dict[str, Any]:
    """Propose bumping `pkg` from `installed_version` to `fixed_version`."""
    is_major_bump = _major_version(installed_version) != _major_version(fixed_version)
    return {
        "package": pkg,
        "from_version": installed_version,
        "to_version": fixed_version,
        "is_major_bump": is_major_bump,
    }
