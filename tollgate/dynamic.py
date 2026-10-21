"""Dynamic-analysis workflow: submit to CAPE, poll lazily, merge the behaviour into the stored scan result."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from . import cape
from .models import Finding, Severity
from .scoring import compute_score, compute_verdict

MAX_WAIT_HOURS = 2


def _now() -> datetime:
    return datetime.now(timezone.utc)


def submit(store, client: cape.CapeClient, name: str, data: bytes, scan_id: int | None, user: str | None) -> dict:
    remote = client.submit_file(name, data)
    task_id = store.create_dynamic_task(scan_id, "cape", str(remote), user)
    return store.get_dynamic_task(task_id)


def merge_into_scan(store, scan_id: int, summary: dict, findings: list[Finding], task_id: int | None = None) -> None:
    """Add dynamic findings to the stored report and re-score it. Safe to run twice (old dynamic findings are replaced)."""
    report = store.get_scan(scan_id)
    if report is None:
        return
    kept = [f for f in report.get("findings", []) if f.get("category") != "dynamic"]
    merged = [Finding(f["rule_id"], f["title"], Severity(f["severity"]), f.get("detail", ""), f.get("category", "general")) for f in kept]
    merged += findings
    report["findings"] = [f.to_dict() for f in merged]
    report.setdefault("metadata", {})["dynamic"] = {**{k: summary[k] for k in summary if k != "findings"}, "task_id": task_id}
    report["score"] = compute_score(merged)
    report["verdict"] = compute_verdict(report["score"], merged)
    store.update_scan_result(scan_id, report, report["verdict"], report["score"])


def refresh(store, client: cape.CapeClient, task_id: int) -> dict | None:
    """Ask CAPE about a task; when its report is ready, summarize it, store it, and update the scan's verdict."""
    task = store.get_dynamic_task(task_id)
    if task is None or task["status"] in ("reported", "failed"):
        return task
    submitted = datetime.fromisoformat(task["submitted_at"])
    try:
        status = client.status(task["remote_id"])
    except cape.CapeError as exc:
        if _now() - submitted > timedelta(hours=MAX_WAIT_HOURS):
            store.update_dynamic_task(task_id, status="failed", error=f"gave up after {MAX_WAIT_HOURS}h: {exc}")
        raise
    if status == "reported":
        summary = cape.summarize_report(client.report(task["remote_id"]))
        findings = cape.dynamic_findings(summary, store)
        summary["findings"] = [f.to_dict() for f in findings]
        store.update_dynamic_task(task_id, status="reported", completed_at=_now().isoformat(timespec="seconds"),
                                  summary_json=json.dumps(summary))
        if task["scan_id"]:
            merge_into_scan(store, task["scan_id"], summary, findings, task_id)
    elif status.startswith("failed") or status == "banned":
        store.update_dynamic_task(task_id, status="failed", error=f"CAPE status: {status}")
    elif _now() - submitted > timedelta(hours=MAX_WAIT_HOURS):
        store.update_dynamic_task(task_id, status="failed", error=f"no result after {MAX_WAIT_HOURS}h (last CAPE status: {status})")
    else:
        store.update_dynamic_task(task_id, status=status)
    return store.get_dynamic_task(task_id)
