#!/usr/bin/env python3
"""
Summarize an AOBTD scan database into a target-agnostic benchmark scorecard.

This deliberately does not try to be a vulnerable-app-specific scoreboard.
Juice Shop has a native challenge counter; most useful benchmark targets do not.
For crAPI/DVWA/WebGoat/VAmPI/DVGA we still want a stable regression signal:

  - did the scan complete?
  - how much surface was captured?
  - how many confirmed findings were produced?
  - are the findings reproducible enough to retest?
  - what classes of issues did AOBTD see?

Usage:
  python3 bench/scorecard.py --db /tmp/aobtd-vampi/scan.db
  python3 bench/scorecard.py --db /tmp/aobtd-vampi/scan.db --json
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.text_factory = lambda b: b.decode("utf-8", "replace")
    conn.row_factory = sqlite3.Row
    return conn


def columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def latest_scan_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT MAX(id) AS id FROM scans").fetchone()
    return None if row is None or row["id"] is None else int(row["id"])


def pick_scan_id(conn: sqlite3.Connection, requested: int | None) -> int:
    scan_id = requested if requested is not None else latest_scan_id(conn)
    if scan_id is None:
        raise SystemExit("No scans found in database")
    return int(scan_id)


def parse_sqlite_time(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def elapsed_seconds(started_at: str | None, finished_at: str | None) -> float | None:
    start = parse_sqlite_time(started_at)
    finish = parse_sqlite_time(finished_at)
    if not start or not finish:
        return None
    return max(0.0, (finish - start).total_seconds())


def count_where(
    conn: sqlite3.Connection, table: str, scan_id: int, where: str = "1=1"
) -> int:
    if not table_exists(conn, table):
        return 0
    row = conn.execute(
        f"SELECT COUNT(*) AS n FROM {table} WHERE scan_id = ? AND ({where})",
        (scan_id,),
    ).fetchone()
    return int(row["n"] if row else 0)


def grouped_counts(
    conn: sqlite3.Connection, table: str, scan_id: int, fields: list[str]
) -> dict[str, int]:
    if not table_exists(conn, table):
        return {}
    available = columns(conn, table)
    fields = [f for f in fields if f in available]
    if not fields:
        return {}
    select = ", ".join(fields)
    rows = conn.execute(
        f"""
        SELECT {select}, COUNT(*) AS n
        FROM {table}
        WHERE scan_id = ?
        GROUP BY {select}
        ORDER BY n DESC
        """,
        (scan_id,),
    ).fetchall()
    out: dict[str, int] = {}
    for row in rows:
        key = " / ".join(str(row[f] if row[f] is not None else "") for f in fields)
        out[key] = int(row["n"])
    return out


def load_run_metadata(db_path: Path) -> dict[str, Any]:
    meta_path = db_path.parent / "run_metadata.json"
    if not meta_path.exists():
        return {}
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return {"metadata_error": "unreadable run_metadata.json"}
    if not isinstance(data, dict):
        return {"metadata_error": "run_metadata.json was not an object"}
    return data


def sum_column(conn: sqlite3.Connection, table: str, scan_id: int, column: str) -> int:
    if not table_exists(conn, table) or column not in columns(conn, table):
        return 0
    row = conn.execute(
        f"SELECT COALESCE(SUM({column}), 0) AS n FROM {table} WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()
    return int(row["n"] if row else 0)


def row_text(row: sqlite3.Row, key: str) -> str:
    try:
        value = row[key]
    except (KeyError, IndexError):
        return ""
    return "" if value is None else str(value)


def proof_quality(row: sqlite3.Row) -> dict[str, Any]:
    endpoint = row_text(row, "endpoint_id").strip()
    vuln_type = row_text(row, "vuln_type").strip().lower()
    description = row_text(row, "description").strip()
    poc_request = row_text(row, "poc_request").strip()
    poc_response = row_text(row, "poc_response").strip()
    steps = row_text(row, "steps_to_reproduce").strip()
    payload = row_text(row, "payload").strip()
    evidence = row_text(row, "evidence").strip()
    target_placeholder = "<target>" in poc_request or "Host: <target>" in poc_request

    if vuln_type == "attack_chain":
        chain_text = "\n".join([description, evidence, steps]).lower()
        checks = {
            "endpoint": bool(endpoint),
            "chain_steps": bool(steps) or "steps:" in chain_text or "chain steps" in chain_text,
            "ingredient_context": "confirmed finding" in chain_text or "confirmed findings" in chain_text,
            "rationale": bool(payload) or "rationale:" in chain_text,
            "evidence": bool(evidence),
            "concrete_target": bool(endpoint) and not target_placeholder,
        }
    else:
        checks = {
            "endpoint": bool(endpoint),
            "request": bool(poc_request),
            "response": bool(poc_response),
            "steps": bool(steps),
            "payload_or_evidence": bool(payload or evidence),
            "concrete_target": bool(endpoint) and not target_placeholder,
        }
    score = sum(1 for ok in checks.values() if ok)
    missing = [name for name, ok in checks.items() if not ok]
    return {
        "score": score,
        "max": len(checks),
        "missing": missing,
        "has_target_placeholder": target_placeholder,
    }


def benchmark_quality(
    scan: sqlite3.Row,
    followups: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []
    status = str(scan["status"] or "").strip().lower()
    if status != "completed":
        reasons.append(f"scan_status:{status or 'unknown'}")
    if not scan["finished_at"]:
        reasons.append("missing_finished_at")

    by_status = followups.get("by_status", {}) if followups else {}
    pending = int(by_status.get("pending", 0) or 0)
    running = int(by_status.get("running", 0) or 0)
    if pending or running:
        reasons.append(f"followups_not_drained:{pending + running}")

    exit_code = metadata.get("exit_code")
    if exit_code not in (None, 0):
        reasons.append(f"process_exit_code:{exit_code}")
    terminated = str(metadata.get("terminated_reason") or "").strip()
    if terminated:
        reasons.append(f"terminated:{terminated}")
    log_health = metadata.get("log_health") if isinstance(metadata.get("log_health"), dict) else {}
    provider_failures = int(log_health.get("provider_failures", 0) or 0)
    if provider_failures:
        reasons.append(f"provider_failures:{provider_failures}")
    scan_config = metadata.get("scan_config") if isinstance(metadata.get("scan_config"), dict) else {}
    llm_mode = str(scan_config.get("llm") or "").strip().lower()
    if llm_mode in {"none", "off", "disabled"}:
        reasons.append("llm_disabled")

    return {
        "comparable": len(reasons) == 0,
        "status": "comparable" if not reasons else "partial",
        "reasons": reasons,
    }


def summarize_findings(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any]:
    if not table_exists(conn, "findings"):
        return {"total": 0, "by_confidence": {}, "by_severity": {}, "confirmed": []}

    cols = columns(conn, "findings")
    wanted = [
        "id",
        "title",
        "description",
        "severity",
        "confidence",
        "vuln_type",
        "endpoint_id",
        "param_name",
        "payload",
        "poc_request",
        "poc_response",
        "steps_to_reproduce",
        "evidence",
    ]
    select_cols = [c for c in wanted if c in cols]
    rows = conn.execute(
        f"""
        SELECT {", ".join(select_cols)}
        FROM findings
        WHERE scan_id = ?
        ORDER BY
          CASE lower(severity)
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            ELSE 4
          END,
          id
        """,
        (scan_id,),
    ).fetchall()

    by_conf = Counter(row_text(r, "confidence") or "unknown" for r in rows)
    by_sev = Counter(row_text(r, "severity") or "unknown" for r in rows)
    by_type = Counter(row_text(r, "vuln_type") or "untyped" for r in rows)
    confirmed = []
    quality_scores = []
    for row in rows:
        if row_text(row, "confidence").lower() != "confirmed":
            continue
        quality = proof_quality(row)
        quality_scores.append(quality["score"])
        confirmed.append(
            {
                "id": row["id"],
                "severity": row_text(row, "severity"),
                "title": row_text(row, "title"),
                "vuln_type": row_text(row, "vuln_type"),
                "endpoint": row_text(row, "endpoint_id"),
                "param": row_text(row, "param_name"),
                "proof_quality": quality,
            }
        )

    ready = sum(1 for f in confirmed if f["proof_quality"]["score"] >= 5)
    avg_quality = round(sum(quality_scores) / len(quality_scores), 2) if quality_scores else 0
    return {
        "total": len(rows),
        "by_confidence": dict(by_conf),
        "by_severity": dict(by_sev),
        "by_type": dict(by_type),
        "confirmed": confirmed,
        "confirmed_count": len(confirmed),
        "retest_ready_confirmed": ready,
        "average_proof_quality": avg_quality,
    }


def summarize_scan(db_path: Path, requested_scan_id: int | None = None) -> dict[str, Any]:
    conn = connect(db_path)
    try:
        scan_id = pick_scan_id(conn, requested_scan_id)
        scan = conn.execute(
            "SELECT id, target, started_at, finished_at, status, config_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if not scan:
            raise SystemExit(f"Scan {scan_id} not found")

        traffic = {
            "total": count_where(conn, "traffic", scan_id),
            "filtered": count_where(conn, "traffic", scan_id, "is_filtered = 1"),
            "duplicates": count_where(conn, "traffic", scan_id, "is_duplicate = 1"),
            "api": count_where(conn, "traffic", scan_id, "is_api = 1"),
            "with_input": count_where(conn, "traffic", scan_id, "has_input = 1 OR has_params = 1"),
            "with_auth": count_where(conn, "traffic", scan_id, "has_auth = 1"),
            "with_errors": count_where(conn, "traffic", scan_id, "has_errors = 1 OR status_code >= 500"),
            "by_method": grouped_counts(conn, "traffic", scan_id, ["method"]),
            "by_status": grouped_counts(conn, "traffic", scan_id, ["status_code"]),
            "by_host": grouped_counts(conn, "traffic", scan_id, ["host"]),
        }
        endpoints = {
            "total": count_where(conn, "endpoints", scan_id),
            "api": count_where(conn, "endpoints", scan_id, "is_api = 1"),
            "with_input": count_where(conn, "endpoints", scan_id, "has_input = 1 OR has_params = 1"),
            "with_auth": count_where(conn, "endpoints", scan_id, "has_auth = 1"),
            "with_errors": count_where(conn, "endpoints", scan_id, "has_errors = 1"),
            "by_method": grouped_counts(conn, "endpoints", scan_id, ["method"]),
        }
        profiles = {
            "total": count_where(conn, "page_profiles", scan_id),
            "api": count_where(conn, "page_profiles", scan_id, "is_api = 1"),
            "with_input": count_where(conn, "page_profiles", scan_id, "has_input = 1"),
            "with_issues": count_where(
                conn,
                "page_profiles",
                scan_id,
                "issues IS NOT NULL AND issues != '' AND issues != '[]'",
            ),
        }
        narrations = {
            "total": count_where(conn, "narrations", scan_id),
            "by_agent_action": dict(
                list(grouped_counts(conn, "narrations", scan_id, ["agent", "action"]).items())[:20]
            ),
        }
        followups = {
            "total": count_where(conn, "follow_ups", scan_id),
            "by_status": grouped_counts(conn, "follow_ups", scan_id, ["status"]),
            "by_action_status": grouped_counts(conn, "follow_ups", scan_id, ["action", "status"]),
        }
        ai = {
            "calls": count_where(conn, "ai_log", scan_id),
            "tokens_in": sum_column(conn, "ai_log", scan_id, "tokens_in"),
            "tokens_out": sum_column(conn, "ai_log", scan_id, "tokens_out"),
            "duration_ms": sum_column(conn, "ai_log", scan_id, "duration_ms"),
            "cost_ucents": sum_column(conn, "ai_log", scan_id, "cost_ucents"),
            "by_agent_action": dict(
                list(grouped_counts(conn, "ai_log", scan_id, ["agent", "action"]).items())[:20]
            ),
            "by_model": grouped_counts(conn, "ai_log", scan_id, ["model_id"]),
        }
        findings = summarize_findings(conn, scan_id)
        metadata = load_run_metadata(db_path)
        quality = benchmark_quality(scan, followups, metadata)

        return {
            "db": str(db_path),
            "scan": {
                "id": int(scan["id"]),
                "target": scan["target"],
                "status": scan["status"],
                "started_at": scan["started_at"],
                "finished_at": scan["finished_at"],
                "elapsed_seconds": elapsed_seconds(scan["started_at"], scan["finished_at"]),
            },
            "traffic": traffic,
            "endpoints": endpoints,
            "profiles": profiles,
            "findings": findings,
            "narrations": narrations,
            "followups": followups,
            "ai": ai,
            "run_metadata": metadata,
            "benchmark_quality": quality,
        }
    finally:
        conn.close()


def fmt_counts(counts: dict[str, int], limit: int = 8) -> str:
    if not counts:
        return "—"
    parts = []
    for key, value in list(counts.items())[:limit]:
        label = str(key).strip() or "unknown"
        parts.append(f"{label}:{value}")
    return ", ".join(parts)


def render_markdown(summary: dict[str, Any]) -> str:
    scan = summary["scan"]
    findings = summary["findings"]
    followups = summary.get("followups", {})
    ai = summary.get("ai", {})
    quality = summary.get("benchmark_quality", {})
    elapsed = scan.get("elapsed_seconds")
    elapsed_label = "—" if elapsed is None else f"{elapsed/60:.1f}m"
    ai_duration = ai.get("duration_ms", 0) or 0
    ai_duration_label = "—" if not ai_duration else f"{ai_duration/1000/60:.1f}m"

    lines = [
        f"## AOBTD benchmark scorecard — scan #{scan['id']}",
        "",
        f"- Target: `{scan['target']}`",
        f"- Status: `{scan['status']}`",
        f"- Benchmark quality: `{quality.get('status', 'unknown')}`" +
        ("" if quality.get("comparable") else f" — {', '.join(quality.get('reasons', []))}"),
        f"- Duration: {elapsed_label}",
        f"- Database: `{summary['db']}`",
        "",
        "| Area | Count | Notes |",
        "|---|---:|---|",
        f"| Traffic | {summary['traffic']['total']} | API {summary['traffic']['api']}, input {summary['traffic']['with_input']}, auth {summary['traffic']['with_auth']}, errors {summary['traffic']['with_errors']} |",
        f"| Endpoints | {summary['endpoints']['total']} | API {summary['endpoints']['api']}, input {summary['endpoints']['with_input']}, auth {summary['endpoints']['with_auth']} |",
        f"| Profiles | {summary['profiles']['total']} | API {summary['profiles']['api']}, with issues {summary['profiles']['with_issues']} |",
        f"| Follow-ups | {followups.get('total', 0)} | {fmt_counts(followups.get('by_status', {}))} |",
        f"| AI calls | {ai.get('calls', 0)} | in {ai.get('tokens_in', 0)}, out {ai.get('tokens_out', 0)}, model time {ai_duration_label} |",
        f"| Findings | {findings['total']} | confirmed {findings.get('confirmed_count', 0)}, retest-ready {findings.get('retest_ready_confirmed', 0)}, avg proof {findings.get('average_proof_quality', 0)}/6 |",
        "",
        f"- Traffic methods: {fmt_counts(summary['traffic']['by_method'])}",
        f"- Traffic status: {fmt_counts(summary['traffic']['by_status'])}",
        f"- Follow-up actions: {fmt_counts(followups.get('by_action_status', {}), 12)}",
        f"- AI models: {fmt_counts(ai.get('by_model', {}), 5)}",
        f"- Finding severities: {fmt_counts(findings['by_severity'])}",
        f"- Finding types: {fmt_counts(findings['by_type'])}",
        "",
        "### Confirmed findings",
        "",
    ]
    confirmed = findings.get("confirmed", [])
    if not confirmed:
        lines.append("_None confirmed._")
    else:
        lines += [
            "| Severity | Type | Endpoint | Proof | Title |",
            "|---|---|---|---:|---|",
        ]
        for f in confirmed:
            quality = f["proof_quality"]
            endpoint = f["endpoint"] or "—"
            title = str(f["title"]).replace("|", "\\|")
            lines.append(
                f"| {f['severity']} | {f['vuln_type'] or '—'} | `{endpoint}` | {quality['score']}/{quality['max']} | {title} |"
            )
    lines.append("")
    gaps = [
        f
        for f in confirmed
        if f["proof_quality"]["missing"] or f["proof_quality"]["has_target_placeholder"]
    ]
    if gaps:
        lines += ["### Reproducibility gaps", ""]
        for f in gaps[:12]:
            missing = ", ".join(f["proof_quality"]["missing"]) or "target placeholder"
            lines.append(f"- #{f['id']} `{f['title']}`: {missing}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, type=Path, help="Path to scan.db")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    args = parser.parse_args()

    summary = summarize_scan(args.db, args.scan_id)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(render_markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
