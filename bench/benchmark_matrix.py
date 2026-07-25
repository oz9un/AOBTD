#!/usr/bin/env python3
"""
Render a suite-level benchmark matrix from AOBTD scorecards.

Per-scan scorecards are excellent for evidence review. This matrix answers a
different question: "What is the latest useful benchmark state per target, and
which rows are actually comparable?"

By default it scans /tmp/aobtd-bench-runs, re-summarizes each adjacent scan.db
with bench/scorecard.py when possible, and renders the latest row per target.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import coverage_gate
import juice_coverage
import scorecard


RUN_DIR_RE = re.compile(r"^\d{8}-\d{6}-(?P<target>.+)$")


@dataclass(frozen=True)
class MatrixRow:
    target: str
    run_id: str
    db: str
    quality: str
    comparable: bool
    reasons: list[str]
    scan_status: str
    duration_seconds: float | None
    traffic: int
    profiles: int
    confirmed: int
    confirmed_types: dict[str, int]
    retest_ready: int
    average_proof_quality: float
    followups: int
    followup_status: dict[str, int]
    ai_calls: int
    ai_tokens_in: int
    ai_tokens_out: int
    coverage_status: str
    coverage_passed: int
    coverage_total: int
    coverage_missing: list[str]
    target_benchmark: dict[str, Any]
    benchmark_ready: bool


def discover_scorecards(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.exists():
        return []
    paths: set[Path] = set()
    for run_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        scorecard_path = run_dir / "scorecard.json"
        scan_db_path = run_dir / "scan.db"
        if scorecard_path.exists() or scan_db_path.exists():
            paths.add(scorecard_path)
    return sorted(paths)


def target_from_path(path: Path, summary: dict[str, Any]) -> str:
    meta = summary.get("run_metadata") if isinstance(summary.get("run_metadata"), dict) else {}
    if meta.get("target"):
        return str(meta["target"])
    match = RUN_DIR_RE.match(path.parent.name)
    if match:
        return match.group("target")
    target_url = str(summary.get("scan", {}).get("target") or "")
    if "://" in target_url:
        return target_url.split("://", 1)[1].split("/", 1)[0]
    return path.parent.name


def load_summary(path: Path) -> dict[str, Any]:
    db_path = path.parent / "scan.db"
    if db_path.exists():
        return scorecard.summarize_scan(db_path)
    return json.loads(path.read_text(encoding="utf-8"))


def load_target_benchmark(run_dir: Path, target: str) -> dict[str, Any]:
    if target == "juice":
        summary_path = run_dir / "juice_coverage.json"
        snapshot_paths = [
            run_dir / "juice_coverage_snapshot.json",
            run_dir / "juice-after.json",
        ]
        if summary_path.exists():
            try:
                data = json.loads(summary_path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001 - matrix should keep rendering on target-specific artifact errors
                return {"kind": "juice", "error": str(exc)}
            if not isinstance(data, dict):
                return {"kind": "juice", "error": "artifact_not_object"}
            return data | {"kind": "juice"}
        for snapshot_path in snapshot_paths:
            if not snapshot_path.exists():
                continue
            try:
                snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
                return juice_coverage.summarize_snapshot(snapshot)
            except Exception as exc:  # noqa: BLE001 - try other fallbacks, or report the last issue
                return {"kind": "juice", "error": str(exc)}
        return {}
    if target != "vulnerableapp":
        return {}
    path = run_dir / "vulnerableapp_benchmark.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - matrix should keep rendering on target-specific artifact errors
        return {"kind": "vulnerableapp", "error": str(exc)}
    if not isinstance(data, dict):
        return {"kind": "vulnerableapp", "error": "artifact_not_object"}
    local = data.get("local") if isinstance(data.get("local"), dict) else {}
    truth = data.get("ground_truth") if isinstance(data.get("ground_truth"), dict) else {}
    native = data.get("native_comparator") if isinstance(data.get("native_comparator"), dict) else {}
    submission = data.get("submission") if isinstance(data.get("submission"), dict) else {}
    out: dict[str, Any] = {
        "kind": "vulnerableapp",
        "ground_truth_total": int(truth.get("total", 0) or 0),
        "ground_truth_insecure": int(truth.get("insecure", 0) or 0),
        "local_matched": int(local.get("matched", 0) or 0),
        "local_expected": int(local.get("expected", 0) or 0),
        "local_coverage_percent": float(local.get("coverage_percent", 0) or 0),
        "comparator_submittable": int(data.get("comparator_submittable", 0) or 0),
        "confirmed_findings": int(data.get("confirmed_findings", 0) or 0),
        "submission_unique": int(submission.get("unique", 0) or 0),
        "submission_duplicates": int(submission.get("duplicates", 0) or 0),
        "submission_unmatched": int(submission.get("unmatched", 0) or 0),
    }
    if native:
        out.update(
            {
                "native_detected": int(native.get("detected", 0) or 0),
                "native_missed": int(native.get("missed", 0) or 0),
                "native_unmatched": int(native.get("unmatched", 0) or 0),
                "native_coverage": float(native.get("coverage", 0) or 0),
            }
        )
    return out


def row_from_scorecard(path: Path) -> MatrixRow:
    summary = load_summary(path)
    target = target_from_path(path, summary)
    db_path = Path(str(summary.get("db") or path.parent / "scan.db"))
    coverage = coverage_for_row(db_path, target)
    target_benchmark = load_target_benchmark(path.parent, target)
    scan = summary.get("scan", {})
    findings = summary.get("findings", {})
    traffic = summary.get("traffic", {})
    profiles = summary.get("profiles", {})
    followups = summary.get("followups", {})
    ai = summary.get("ai", {})
    quality = summary.get("benchmark_quality") or {}
    comparable = bool(quality.get("comparable"))
    quality_status = str(quality.get("status") or ("comparable" if comparable else "unknown"))
    confirmed_types: dict[str, int] = {}
    for finding in findings.get("confirmed", []) or []:
        vuln_type = str(finding.get("vuln_type") or "untyped")
        confirmed_types[vuln_type] = confirmed_types.get(vuln_type, 0) + 1
    return MatrixRow(
        target=target,
        run_id=path.parent.name,
        db=str(db_path),
        quality=quality_status,
        comparable=comparable,
        reasons=[str(r) for r in quality.get("reasons", [])],
        scan_status=str(scan.get("status") or ""),
        duration_seconds=scan.get("elapsed_seconds"),
        traffic=int(traffic.get("total", 0) or 0),
        profiles=int(profiles.get("total", 0) or 0),
        confirmed=int(findings.get("confirmed_count", 0) or 0),
        confirmed_types=confirmed_types,
        retest_ready=int(findings.get("retest_ready_confirmed", 0) or 0),
        average_proof_quality=float(findings.get("average_proof_quality", 0) or 0),
        followups=int(followups.get("total", 0) or 0),
        followup_status={str(k): int(v) for k, v in (followups.get("by_status", {}) or {}).items()},
        ai_calls=int(ai.get("calls", 0) or 0),
        ai_tokens_in=int(ai.get("tokens_in", 0) or 0),
        ai_tokens_out=int(ai.get("tokens_out", 0) or 0),
        coverage_status=str(coverage.get("status") or "unknown"),
        coverage_passed=int(coverage.get("passed", 0) or 0),
        coverage_total=int(coverage.get("total", 0) or 0),
        coverage_missing=[str(x) for x in coverage.get("missing", [])],
        target_benchmark=target_benchmark,
        benchmark_ready=benchmark_ready(
            comparable,
            str(coverage.get("status") or "unknown"),
            int(coverage.get("total", 0) or 0),
        ),
    )


def benchmark_ready(comparable: bool, coverage_status: str, coverage_total: int) -> bool:
    if not comparable:
        return False
    if coverage_total == 0:
        # No target-specific coverage gate is defined. Do not block unknown
        # external targets on this benchmark-suite-only signal.
        return coverage_status != "error"
    return coverage_status == "pass"


def coverage_for_row(db_path: Path, target: str) -> dict[str, Any]:
    if not db_path.exists():
        return {"status": "unknown", "passed": 0, "total": 0, "missing": []}
    try:
        return coverage_gate.evaluate_coverage(db_path, target=target)
    except Exception as exc:  # noqa: BLE001 - matrix should not fail on coverage diagnostics
        return {"status": "error", "passed": 0, "total": 0, "missing": [f"coverage_error:{exc}"]}


def collect_rows(root: Path) -> list[MatrixRow]:
    rows: list[MatrixRow] = []
    for path in discover_scorecards(root):
        try:
            rows.append(row_from_scorecard(path))
        except Exception as exc:  # noqa: BLE001 - matrix should keep rendering other runs
            rows.append(
                MatrixRow(
                    target=path.parent.name,
                    run_id=path.parent.name,
                    db=str(path.parent / "scan.db"),
                    quality="unreadable",
                    comparable=False,
                    reasons=[f"scorecard_error:{exc}"],
                    scan_status="unknown",
                    duration_seconds=None,
                    traffic=0,
                    profiles=0,
                    confirmed=0,
                    confirmed_types={},
                    retest_ready=0,
                    average_proof_quality=0,
                    followups=0,
                    followup_status={},
                    ai_calls=0,
                    ai_tokens_in=0,
                    ai_tokens_out=0,
                    coverage_status="unknown",
                    coverage_passed=0,
                    coverage_total=0,
                    coverage_missing=[],
                    target_benchmark={},
                    benchmark_ready=False,
                )
            )
    return rows


def latest_per_target(
    rows: list[MatrixRow],
    comparable_only: bool = False,
    benchmark_ready_only: bool = False,
) -> list[MatrixRow]:
    selected: dict[str, MatrixRow] = {}
    for row in rows:
        if benchmark_ready_only and not row.benchmark_ready:
            continue
        if comparable_only and not row.comparable:
            continue
        prior = selected.get(row.target)
        if prior is None or row.run_id > prior.run_id:
            selected[row.target] = row
    return sorted(selected.values(), key=lambda r: r.target)


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    return f"{seconds / 60:.1f}m"


def fmt_reasons(row: MatrixRow) -> str:
    if row.comparable:
        return "—"
    return ", ".join(row.reasons) if row.reasons else "not comparable"


def fmt_followups(row: MatrixRow) -> str:
    if not row.followup_status:
        return "—"
    return ", ".join(f"{k}:{v}" for k, v in sorted(row.followup_status.items()))


def fmt_coverage(row: MatrixRow) -> str:
    if row.coverage_total == 0:
        return row.coverage_status
    return f"{row.coverage_status} {row.coverage_passed}/{row.coverage_total}"


def fmt_coverage_missing(row: MatrixRow) -> str:
    if not row.coverage_missing:
        return "—"
    return ", ".join(row.coverage_missing[:4])


def fmt_confirmed_types(row: MatrixRow) -> str:
    if not row.confirmed_types:
        return "—"
    return ", ".join(f"{k}:{v}" for k, v in sorted(row.confirmed_types.items()))


def fmt_target_benchmark(row: MatrixRow) -> str:
    data = row.target_benchmark
    if not data:
        return "—"
    if data.get("error"):
        return f"{data.get('kind', 'target')}: error"
    if data.get("kind") == "vulnerableapp":
        matched = int(data.get("local_matched", 0) or 0)
        expected = int(data.get("local_expected", 0) or 0)
        percent = float(data.get("local_coverage_percent", 0) or 0)
        parts = [f"local {matched}/{expected} ({percent:g}%)"]
        if int(data.get("submission_unique", 0) or 0) or int(data.get("submission_unmatched", 0) or 0):
            parts.append(
                f"submit unique {int(data.get('submission_unique', 0) or 0)}, "
                f"dup {int(data.get('submission_duplicates', 0) or 0)}, "
                f"unmatched {int(data.get('submission_unmatched', 0) or 0)}"
            )
        if "native_detected" in data:
            detected = int(data.get("native_detected", 0) or 0)
            missed = int(data.get("native_missed", 0) or 0)
            unmatched = int(data.get("native_unmatched", 0) or 0)
            total = detected + missed
            parts.append(f"native {detected}/{total}, unmatched {unmatched}")
        return "; ".join(parts)
    if data.get("kind") == "juice":
        solved = int(data.get("solved", 0) or 0)
        total = int(data.get("total", 0) or 0)
        percent = float(data.get("solved_percent", 0) or 0)
        parts = [f"solved {solved}/{total} ({percent:g}%)"]
        enabled_total = int(data.get("enabled_total", 0) or 0)
        enabled_solved = int(data.get("enabled_solved", 0) or 0)
        if enabled_total and enabled_total != total:
            enabled_percent = float(data.get("enabled_solved_percent", 0) or 0)
            parts.append(f"enabled {enabled_solved}/{enabled_total} ({enabled_percent:g}%)")
        return "; ".join(parts)
    return str(data)


def fmt_reasons_and_coverage(row: MatrixRow) -> str:
    parts: list[str] = []
    if not row.comparable:
        parts.append(", ".join(row.reasons) if row.reasons else "not comparable")
    if row.coverage_total > 0 and row.coverage_status != "pass":
        parts.append("coverage missing: " + fmt_coverage_missing(row))
    return "; ".join(parts) if parts else "—"


def render_markdown(rows: list[MatrixRow]) -> str:
    lines = [
        "# AOBTD benchmark matrix",
        "",
        "| Target | Ready | Quality | Coverage | Target score | Scan | Duration | Traffic | Profiles | Confirmed | Types | Retest | Proof | Follow-ups | AI calls | Reasons | DB |",
        "|---|---|---|---|---|---|---:|---:|---:|---:|---|---:|---:|---|---:|---|---|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    row.target,
                    "yes" if row.benchmark_ready else "no",
                    row.quality,
                    fmt_coverage(row),
                    fmt_target_benchmark(row),
                    row.scan_status,
                    fmt_duration(row.duration_seconds),
                    str(row.traffic),
                    str(row.profiles),
                    str(row.confirmed),
                    fmt_confirmed_types(row),
                    str(row.retest_ready),
                    f"{row.average_proof_quality}/6",
                    fmt_followups(row),
                    str(row.ai_calls),
                    fmt_reasons_and_coverage(row).replace("|", "\\|"),
                    f"`{row.db}`",
                ]
            )
            + " |"
        )
    comparable = sum(1 for row in rows if row.comparable)
    ready = sum(1 for row in rows if row.benchmark_ready)
    partial = len(rows) - comparable
    lines += [
        "",
        f"Benchmark-ready rows: `{ready}` · Comparable rows: `{comparable}` · Partial/unusable rows: `{partial}`",
    ]
    return "\n".join(lines)


def rows_to_json(rows: list[MatrixRow]) -> list[dict[str, Any]]:
    return [
        {
            "target": r.target,
            "run_id": r.run_id,
            "db": r.db,
            "quality": r.quality,
            "comparable": r.comparable,
            "reasons": r.reasons,
            "scan_status": r.scan_status,
            "duration_seconds": r.duration_seconds,
            "traffic": r.traffic,
            "profiles": r.profiles,
            "confirmed": r.confirmed,
            "confirmed_types": r.confirmed_types,
            "retest_ready": r.retest_ready,
            "average_proof_quality": r.average_proof_quality,
            "followups": r.followups,
            "followup_status": r.followup_status,
            "ai_calls": r.ai_calls,
            "ai_tokens_in": r.ai_tokens_in,
            "ai_tokens_out": r.ai_tokens_out,
            "coverage_status": r.coverage_status,
            "coverage_passed": r.coverage_passed,
            "coverage_total": r.coverage_total,
            "coverage_missing": r.coverage_missing,
            "target_benchmark": r.target_benchmark,
            "benchmark_ready": r.benchmark_ready,
        }
        for r in rows
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/tmp/aobtd-bench-runs"))
    parser.add_argument("--all", action="store_true", help="Render every scorecard row, not only latest per target")
    parser.add_argument("--comparable-only", action="store_true", help="Only include comparable rows")
    parser.add_argument(
        "--benchmark-ready-only",
        action="store_true",
        help="Only include rows with clean scan quality and passing target coverage gate",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    rows = collect_rows(args.root)
    if args.comparable_only and not args.benchmark_ready_only:
        rows = [row for row in rows if row.comparable]
    if not args.all:
        rows = latest_per_target(rows, benchmark_ready_only=args.benchmark_ready_only)
    else:
        if args.benchmark_ready_only:
            rows = [row for row in rows if row.benchmark_ready]
        rows = sorted(rows, key=lambda r: (r.target, r.run_id))

    if args.json:
        print(json.dumps(rows_to_json(rows), indent=2, sort_keys=True))
    else:
        print(render_markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
