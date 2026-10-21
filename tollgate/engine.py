"""Orchestrates triage, type-specific analyzers, threat intel and YARA into one Report."""
from __future__ import annotations

import hashlib
import os

from . import lnk_analyzer, pdf_analyzer, pe_analyzer, triage
from .models import SEVERITY_ORDER, Finding, Report, Severity as S
from .scoring import compute_score, compute_verdict
from .urlcheck import analyze_url, defang_text

DEFAULT_MAX_SIZE = 200 * 1024 * 1024
MAX_ARTIFACTS = 12
MAX_DEPTH = 2


def _file_intel(store, hashes: dict) -> list[Finding]:
    findings = []
    for kind in ("sha256", "sha1", "md5"):
        row = store.lookup_ioc(kind, hashes[kind])
        if row:
            findings.append(Finding(
                "INTEL_HASH_MATCH", f"Known malicious file ({row['family'] or 'unknown family'})",
                S(row["severity"]), f"{kind} {hashes[kind]} | source={row['source']}"
                + (f" | {row['note']}" if row["note"] else ""), "intel"))
            break
    prev = store.previous_sightings(hashes["sha256"])
    if prev["count"]:
        findings.append(Finding(
            "FILE_SEEN_BEFORE", f"This exact file was scanned {prev['count']} time(s) before", S.INFO,
            f"First seen {prev['first']}, last seen {prev['last']}.", "history"))
    return findings


def _pe_intel(store, pe_meta: dict) -> list[Finding]:
    imphash = (pe_meta.get("imports") or {}).get("imphash")
    if store and imphash:
        row = store.lookup_ioc("imphash", imphash)
        if row:
            return [Finding(
                "INTEL_IMPHASH_MATCH", f"Import hash matches known malware ({row['family'] or 'unknown family'})",
                S.HIGH, f"imphash {imphash} | source={row['source']}. Shared by builds of the same family; "
                "collisions with unrelated files are possible.", "intel")]
    return []


def _url_checks(urls: list[str], store) -> list[Finding]:
    known, suspicious = [], []
    for u in urls:
        ur = analyze_url(u, store)
        if ur.intel:
            known.append(ur)
        elif ur.verdict != "Clean":
            top = sorted(ur.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))[0]
            suspicious.append(f"{ur.defanged} ({top.title})")
    findings = []
    if known:
        worst = min((S(r["severity"]) for ur in known for r in ur.intel), key=SEVERITY_ORDER.index)
        lines = [f"{ur.defanged} -> " + ", ".join(f"{r['ioc_type']}:{defang_text(r['value'])}" for r in ur.intel)
                 for ur in known[:5]]
        findings.append(Finding("INTEL_URL_MATCH", "Embedded URL/domain matches threat intel", worst,
                                "; ".join(lines), "intel"))
    if suspicious:
        findings.append(Finding("URL_SUSPICIOUS", f"{len(suspicious)} suspicious embedded URL(s)", S.MEDIUM,
                                "; ".join(suspicious[:5]), "url"))
    return findings


def _scan_artifacts(artifacts, store, yara_engine, seen_ids: set, urls: list, depth: int = 0):
    """Examine byte blobs a parser pulled out (decoded commands, embedded files, appended data) like top-level files."""
    findings: list[Finding] = []
    summary: list[dict] = []
    for label, blob in artifacts[:MAX_ARTIFACTS]:
        kind = triage.detect_type(blob[:4096])
        md5 = hashlib.md5(blob, usedforsecurity=False).hexdigest()
        sha = hashlib.sha256(blob).hexdigest()
        summary.append({"label": label, "size": len(blob), "type": kind, "sha256": sha})
        new: list[Finding] = []
        if store:
            row = store.lookup_ioc("sha256", sha) or store.lookup_ioc("md5", md5)
            if row:
                new.append(Finding("INTEL_HASH_MATCH", f"known malware ({row['family'] or 'unknown family'})",
                                   S(row["severity"]), f"sha256 {sha} | source={row['source']}", "intel"))
        if yara_engine is not None:
            new += yara_engine.scan(blob)[0]
        if kind == "pe":
            pf, pm = pe_analyzer.analyze(blob, extra_rules=store.enabled_rules() if store else [])
            new += pf
            urls += pm.get("urls", [])
            new += _pe_intel(store, pm)
        elif kind in ("lnk", "pdf") and depth < MAX_DEPTH:
            fn = lnk_analyzer.analyze if kind == "lnk" else pdf_analyzer.analyze
            sf, sm, sa = fn(blob)
            new += sf
            urls += sm.get("urls", [])
            nested_f, nested_s = _scan_artifacts(sa, store, yara_engine, seen_ids, urls, depth + 1)
            new += nested_f
            summary += nested_s
        for f in new:
            if f.rule_id in seen_ids:
                continue
            seen_ids.add(f.rule_id)
            findings.append(Finding(f.rule_id, f"{label}: {f.title}", f.severity, f.detail, f.category))
    return findings, summary


def analyze_bytes(data: bytes, name: str, store=None, source: str = "cli", record: bool = True,
                  yara_engine=None, user: str | None = None) -> Report:
    t = triage.run(data, name)
    findings = list(t.findings)
    metadata: dict = {}
    if store:
        findings += _file_intel(store, t.hashes)

    urls: list[str] = []
    artifacts: list[tuple[str, bytes]] = []
    if t.detected_type == "pe":
        pe_findings, pe_meta = pe_analyzer.analyze(data, extra_rules=store.enabled_rules() if store else [])
        findings += pe_findings
        metadata["pe"] = pe_meta
        findings += _pe_intel(store, pe_meta)
        urls += pe_meta.get("urls", [])
    elif t.detected_type == "lnk":
        lf, lm, artifacts = lnk_analyzer.analyze(data)
        findings += lf
        metadata["lnk"] = lm
        urls += lm.get("urls", [])
    elif t.detected_type == "pdf":
        pf, pm, artifacts = pdf_analyzer.analyze(data)
        findings += pf
        metadata["pdf"] = pm
        urls += pm.get("urls", [])

    if yara_engine is not None:
        y_findings, y_summary = yara_engine.scan(data)
        findings += y_findings
        metadata["yara"] = {"rules_loaded": yara_engine.rule_count(), "matches": y_summary}

    seen_ids = {f.rule_id for f in findings}
    if artifacts:
        af, summary = _scan_artifacts(artifacts, store, yara_engine, seen_ids, urls)
        findings += af
        metadata["artifacts"] = summary
    findings += _url_checks(list(dict.fromkeys(urls))[:15], store)

    score = compute_score(findings)
    report = Report(filename=name, size=len(data), hashes=t.hashes, detected_type=t.detected_type,
                    findings=findings, score=score, verdict=compute_verdict(score, findings), metadata=metadata)
    if store and record:
        report.scan_id = store.record_scan(report, source, user)
    return report


def analyze_file(path: str, display_name: str | None = None, max_size: int = DEFAULT_MAX_SIZE,
                 store=None, source: str = "cli", record: bool = True, yara_engine=None) -> Report:
    size = os.path.getsize(path)
    if size > max_size:
        raise ValueError(f"file is {size} bytes, over the {max_size} byte limit")
    with open(path, "rb") as fh:  # read-only; bytes are parsed, never executed
        data = fh.read()
    return analyze_bytes(data, display_name or os.path.basename(path), store, source, record, yara_engine)
