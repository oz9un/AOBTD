#!/usr/bin/env python3
"""
Pass/fail regression gate for AOBTD intentionally vulnerable benchmarks.

The matrix is descriptive. This gate is prescriptive: it asserts that the
current benchmark-ready baselines still have enough signal, proof quality, and
target terrain coverage to be useful as regression evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import benchmark_matrix


DEFAULT_BASELINES_PATH = Path(__file__).resolve().parent / "regression_baselines.json"
BaselineMap = dict[str, dict[str, Any]]
REQUIRED_BASELINE_FIELDS = ("min_confirmed", "min_retest_ready", "min_avg_proof")


def load_baselines(path: Path = DEFAULT_BASELINES_PATH) -> BaselineMap:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - CLI should show exact baseline loading issue
        raise SystemExit(f"Could not read regression baselines {path}: {exc}") from exc
    if not isinstance(data, dict) or not data:
        raise SystemExit(f"Regression baselines must be a non-empty object: {path}")
    baselines: BaselineMap = {}
    for target, raw in data.items():
        if not isinstance(target, str) or not target.strip():
            raise SystemExit(f"Regression baseline target names must be non-empty strings: {path}")
        if not isinstance(raw, dict):
            raise SystemExit(f"Regression baseline for {target!r} must be an object: {path}")
        missing = [field for field in REQUIRED_BASELINE_FIELDS if field not in raw]
        if missing:
            raise SystemExit(f"Regression baseline for {target!r} missing fields: {', '.join(missing)}")
        try:
            min_confirmed = int(raw["min_confirmed"])
            min_retest_ready = int(raw["min_retest_ready"])
            min_avg_proof = float(raw["min_avg_proof"])
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"Regression baseline for {target!r} contains non-numeric threshold: {exc}") from exc
        if min_confirmed < 0 or min_retest_ready < 0 or min_avg_proof < 0:
            raise SystemExit(f"Regression baseline for {target!r} cannot contain negative thresholds")
        required_types_raw = raw.get("required_types", [])
        if not isinstance(required_types_raw, list) or not all(isinstance(x, str) and x.strip() for x in required_types_raw):
            raise SystemExit(f"Regression baseline for {target!r} required_types must be a list of non-empty strings")
        baselines[target] = {
            "min_confirmed": min_confirmed,
            "min_retest_ready": min_retest_ready,
            "min_avg_proof": min_avg_proof,
            "required_types": sorted({str(x).strip() for x in required_types_raw}),
        }
    return baselines


def candidate_rows(rows: list[benchmark_matrix.MatrixRow], mode: str) -> list[benchmark_matrix.MatrixRow]:
    if mode == "latest-ready":
        return benchmark_matrix.latest_per_target(rows, benchmark_ready_only=True)
    if mode == "latest":
        return benchmark_matrix.latest_per_target(rows)
    raise ValueError(f"unknown gate mode: {mode}")


def evaluate_rows(
    rows: list[benchmark_matrix.MatrixRow],
    baselines: BaselineMap | None = None,
    mode: str = "latest-ready",
) -> dict[str, Any]:
    baselines = baselines or load_baselines()
    selected = {row.target: row for row in candidate_rows(rows, mode)}
    checks: list[dict[str, Any]] = []
    for target, baseline in sorted(baselines.items()):
        row = selected.get(target)
        if row is None:
            checks.append(
                {
                    "target": target,
                    "ok": False,
                    "reason": "missing_benchmark_row",
                    "baseline": baseline,
                    "row": None,
                }
            )
            continue

        failures: list[str] = []
        if not row.benchmark_ready:
            failures.append("not_benchmark_ready")
        if row.confirmed < int(baseline["min_confirmed"]):
            failures.append(f"confirmed:{row.confirmed}<{baseline['min_confirmed']}")
        if row.retest_ready < int(baseline["min_retest_ready"]):
            failures.append(f"retest_ready:{row.retest_ready}<{baseline['min_retest_ready']}")
        if row.average_proof_quality < float(baseline["min_avg_proof"]):
            failures.append(f"avg_proof:{row.average_proof_quality}<{baseline['min_avg_proof']}")
        required_types = [str(x) for x in baseline.get("required_types", [])]
        missing_types = [vuln_type for vuln_type in required_types if row.confirmed_types.get(vuln_type, 0) <= 0]
        if missing_types:
            failures.append("missing_types:" + ",".join(missing_types))
        checks.append(
            {
                "target": target,
                "ok": not failures,
                "reason": ", ".join(failures) if failures else "",
                "baseline": baseline,
                "row": {
                    "run_id": row.run_id,
                    "db": row.db,
                    "benchmark_ready": row.benchmark_ready,
                    "confirmed": row.confirmed,
                    "confirmed_types": row.confirmed_types,
                    "retest_ready": row.retest_ready,
                    "average_proof_quality": row.average_proof_quality,
                    "coverage": f"{row.coverage_status} {row.coverage_passed}/{row.coverage_total}",
                },
            }
        )
    failed = [check for check in checks if not check["ok"]]
    return {
        "status": "pass" if not failed else "fail",
        "mode": mode,
        "passed": len(checks) - len(failed),
        "total": len(checks),
        "checks": checks,
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# AOBTD benchmark regression gate",
        "",
        f"- Status: `{result['status']}`",
        f"- Mode: `{result['mode']}`",
        f"- Passed: `{result['passed']}/{result['total']}`",
        "",
        "| Target | Status | Run | Confirmed | Types | Retest | Proof | Coverage | Reason |",
        "|---|---|---|---:|---|---:|---:|---|---|",
    ]
    for check in result["checks"]:
        row = check.get("row") or {}
        types = row.get("confirmed_types") or {}
        type_label = ", ".join(f"{k}:{v}" for k, v in sorted(types.items())) if types else "—"
        lines.append(
            "| "
            + " | ".join(
                [
                    check["target"],
                    "pass" if check["ok"] else "fail",
                    f"`{row.get('run_id', '—')}`",
                    str(row.get("confirmed", "—")),
                    type_label,
                    str(row.get("retest_ready", "—")),
                    str(row.get("average_proof_quality", "—")),
                    str(row.get("coverage", "—")),
                    check.get("reason") or "—",
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/tmp/aobtd-bench-runs"))
    parser.add_argument(
        "--mode",
        choices=["latest-ready", "latest"],
        default="latest-ready",
        help="'latest-ready' checks the latest ready row per target; 'latest' requires the newest row itself to pass.",
    )
    parser.add_argument("--baselines", type=Path, default=DEFAULT_BASELINES_PATH)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = evaluate_rows(
        benchmark_matrix.collect_rows(args.root),
        baselines=load_baselines(args.baselines),
        mode=args.mode,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_markdown(result))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
