"""Data models shared by every analyzer module."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 10,
    Severity.HIGH: 25,
    Severity.CRITICAL: 50,
}

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


@dataclass
class Finding:
    """One piece of evidence. Every verdict must be explainable by findings."""

    rule_id: str
    title: str
    severity: Severity
    detail: str = ""
    category: str = "general"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "category": self.category,
        }


@dataclass
class Report:
    filename: str
    size: int
    hashes: dict
    detected_type: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "Clean"
    metadata: dict = field(default_factory=dict)
    scan_id: int | None = None

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "filename": self.filename,
            "size": self.size,
            "hashes": self.hashes,
            "detected_type": self.detected_type,
            "verdict": self.verdict,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }
