"""Turn findings into a score and a verdict.

Weights are deliberately simple and transparent. Tune them against a real
corpus (benign + malware) before trusting them; see README roadmap.
"""
from __future__ import annotations

from .models import SEVERITY_WEIGHT, Finding, Severity

MALICIOUS_AT = 60
SUSPICIOUS_AT = 15


def compute_score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))


def compute_verdict(score: int, findings: list[Finding] | None = None) -> str:
    # A critical threat-intel hit (known-bad hash/URL/domain) or a sandbox-named malware family is decisive on its own.
    if findings and any(f.rule_id.startswith(("INTEL_", "DYN_FAMILY")) and f.severity == Severity.CRITICAL for f in findings):
        return "Malicious"
    if score >= MALICIOUS_AT:
        return "Malicious"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Clean"
