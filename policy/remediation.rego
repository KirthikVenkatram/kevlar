package ci.v1

# This is the USP: exploitability, not severity, drives the verdict. The
# orchestrator calls `opa eval` on this deterministically after the model
# proposes a remediation — the model cannot skip or influence this gate.
#
# input:
#   cve, package, epss (float), in_kev (bool)
#   bump: {package, from_version, to_version, is_major_bump}
# data:
#   epss_threshold (float), allowlist (array of package names)

import rego.v1

exploitable if input.in_kev

exploitable if input.epss > data.epss_threshold

allowlisted if input.package in data.allowlist

# auto: exploitable, a safe (non-major) bump, and the package is allowlisted.
# human: exploitable but the bump is major or the package isn't allowlisted.
# reject: not exploitable at all.
remediation := "auto" if {
	exploitable
	not input.bump.is_major_bump
	allowlisted
} else := "human" if {
	exploitable
} else := "reject"
