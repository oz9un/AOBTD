#!/usr/bin/env python3
"""
Exact OWASP Juice Shop challenge coverage helper for local benchmark runs.

This is intentionally a bench-only adapter. AOBTD's scanner must not learn
Juice Shop challenge keys or solve conditions; this script only measures the
local training app before/after a scan.

Usage:
  python bench/juice_coverage.py snapshot --target http://127.0.0.1:3000 --out before.json
  python bench/juice_coverage.py snapshot --target http://127.0.0.1:3000 --out after.json
  python bench/juice_coverage.py diff --before before.json --after after.json --format markdown
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any


def fetch_challenges(target: str) -> dict[str, Any]:
    url = target.rstrip("/") + "/api/Challenges"
    req = urllib.request.Request(url, headers={"User-Agent": "AOBTD/bench-juice-coverage"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read()
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise ValueError(f"{url} did not return a Juice Shop challenge payload")
    return data


def load_snapshot(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise ValueError(f"{path} is not a Juice Shop challenge snapshot")
    return data


def solved(challenges: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in challenges.get("data", []):
        if item.get("solved") is True:
            out[str(item.get("key", ""))] = item
    return out


def summarize_snapshot(challenges: dict[str, Any]) -> dict[str, Any]:
    """Summarize one Juice Shop /api/Challenges snapshot.

    Diff reports are best when the runner captures before+after snapshots. For
    normal benchmark matrix rendering we still want a compact, durable target
    score from the post-scan state alone.
    """
    items = challenges.get("data", [])
    if not isinstance(items, list):
        raise ValueError("Juice Shop challenge snapshot is missing data list")
    solved_items = solved(challenges)
    enabled_items = [item for item in items if not item.get("disabledEnv")]
    enabled_keys = {str(item.get("key", "")) for item in enabled_items}
    solved_enabled = sorted(set(solved_items) & enabled_keys)

    categories: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "solved": 0})
    enabled_categories: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "solved": 0})
    for item in items:
        key = str(item.get("key", ""))
        category = str(item.get("category") or "Uncategorized")
        categories[category]["total"] += 1
        if key in solved_items:
            categories[category]["solved"] += 1
        if not item.get("disabledEnv"):
            enabled_categories[category]["total"] += 1
            if key in solved_items:
                enabled_categories[category]["solved"] += 1

    total = len(items)
    solved_total = len(solved_items)
    enabled_total = len(enabled_items)
    enabled_solved = len(solved_enabled)
    return {
        "kind": "juice",
        "total": total,
        "solved": solved_total,
        "solved_percent": round((100 * solved_total / total) if total else 0, 2),
        "enabled_total": enabled_total,
        "enabled_solved": enabled_solved,
        "enabled_solved_percent": round((100 * enabled_solved / enabled_total) if enabled_total else 0, 2),
        "solved_keys": sorted(solved_items),
        "categories": dict(sorted(categories.items())),
        "enabled_categories": dict(sorted(enabled_categories.items())),
    }


def render_summary(summary: dict[str, Any]) -> str:
    total = int(summary.get("total", 0) or 0)
    solved_count = int(summary.get("solved", 0) or 0)
    pct = float(summary.get("solved_percent", 0) or 0)
    enabled_total = int(summary.get("enabled_total", 0) or 0)
    enabled_solved = int(summary.get("enabled_solved", 0) or 0)
    enabled_pct = float(summary.get("enabled_solved_percent", 0) or 0)
    lines = [
        "# Juice Shop Exact Coverage",
        "",
        f"- Solved challenges: `{solved_count}/{total}` ({pct:.1f}%)",
    ]
    if enabled_total != total:
        lines.append(f"- Enabled-env solved: `{enabled_solved}/{enabled_total}` ({enabled_pct:.1f}%)")
    lines += [
        "",
        "## Category Coverage",
        "",
        "| Category | Total | Solved |",
        "| --- | ---: | ---: |",
    ]
    for category, row in (summary.get("categories") or {}).items():
        lines.append(f"| {category} | {row.get('total', 0)} | {row.get('solved', 0)} |")
    return "\n".join(lines) + "\n"


def by_key(challenges: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("key", "")): item for item in challenges.get("data", [])}


def diff_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_by_key = by_key(before)
    after_by_key = by_key(after)
    before_solved = solved(before)
    after_solved = solved(after)
    newly_solved_keys = sorted(set(after_solved) - set(before_solved))
    regressed_keys = sorted(set(before_solved) - set(after_solved))
    total = len(after_by_key)
    enabled_keys = {
        key for key, item in after_by_key.items()
        if not item.get("disabledEnv")
    }
    before_enabled_solved = len(set(before_solved) & enabled_keys)
    after_enabled_solved = len(set(after_solved) & enabled_keys)
    disabled_unsolved = sorted(
        key for key, item in after_by_key.items()
        if item.get("disabledEnv") and key not in after_solved
    )

    categories: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "before": 0, "after": 0, "new": 0})
    enabled_categories: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "before": 0, "after": 0, "new": 0})
    for key, item in after_by_key.items():
        category = str(item.get("category") or "Uncategorized")
        categories[category]["total"] += 1
        if key in before_solved:
            categories[category]["before"] += 1
        if key in after_solved:
            categories[category]["after"] += 1
        if key in newly_solved_keys:
            categories[category]["new"] += 1
        if key in enabled_keys:
            enabled_categories[category]["total"] += 1
            if key in before_solved:
                enabled_categories[category]["before"] += 1
            if key in after_solved:
                enabled_categories[category]["after"] += 1
            if key in newly_solved_keys:
                enabled_categories[category]["new"] += 1

    def challenge_row(key: str) -> dict[str, Any]:
        item = after_by_key.get(key) or before_by_key.get(key) or {"key": key}
        return {
            "key": key,
            "name": item.get("name", key),
            "category": item.get("category", "Uncategorized"),
            "difficulty": item.get("difficulty"),
            "disabledEnv": item.get("disabledEnv"),
        }

    return {
        "total": total,
        "before_solved": len(before_solved),
        "after_solved": len(after_solved),
        "enabled_total": len(enabled_keys),
        "before_enabled_solved": before_enabled_solved,
        "after_enabled_solved": after_enabled_solved,
        "newly_solved": [challenge_row(k) for k in newly_solved_keys],
        "regressed": [challenge_row(k) for k in regressed_keys],
        "disabled_unsolved": [challenge_row(k) for k in disabled_unsolved],
        "categories": dict(sorted(categories.items())),
        "enabled_categories": dict(sorted(enabled_categories.items())),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    total = report["total"]
    before = report["before_solved"]
    after = report["after_solved"]
    new = len(report["newly_solved"])
    pct = (after * 100 / total) if total else 0
    enabled_total = report.get("enabled_total", total)
    enabled_before = report.get("before_enabled_solved", before)
    enabled_after = report.get("after_enabled_solved", after)
    enabled_pct = (enabled_after * 100 / enabled_total) if enabled_total else 0
    lines.append(f"# Juice Shop Exact Coverage")
    lines.append("")
    lines.append(f"- Before solved: `{before}/{total}`")
    lines.append(f"- After solved: `{after}/{total}` ({pct:.1f}%)")
    if enabled_total != total:
        lines.append(
            f"- Enabled-env solved: `{enabled_after}/{enabled_total}` ({enabled_pct:.1f}%) "
            f"(before `{enabled_before}/{enabled_total}`; excludes challenges disabled for this runtime)"
        )
    lines.append(f"- Newly solved: `{new}`")
    if report["regressed"]:
        lines.append(f"- Regressed solved challenges: `{len(report['regressed'])}`")
    lines.append("")
    lines.append("## Newly Solved")
    lines.append("")
    if report["newly_solved"]:
        lines.append("| Challenge | Key | Category | Difficulty |")
        lines.append("| --- | --- | --- | ---: |")
        for item in report["newly_solved"]:
            lines.append(
                f"| {item['name']} | `{item['key']}` | {item['category']} | {item.get('difficulty') or ''} |"
            )
    else:
        lines.append("(none)")
    lines.append("")
    lines.append("## Category Coverage")
    lines.append("")
    lines.append("| Category | Total | Before | After | New |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for category, row in report["categories"].items():
        lines.append(
            f"| {category} | {row['total']} | {row['before']} | {row['after']} | {row['new']} |"
        )
    if report.get("disabled_unsolved"):
        lines.append("")
        lines.append("## Disabled in This Runtime and Still Unsolved")
        lines.append("")
        lines.append("| Challenge | Key | Category | Disabled Env |")
        lines.append("| --- | --- | --- | --- |")
        for item in report["disabled_unsolved"]:
            disabled = item.get("disabledEnv") or "runtime-disabled"
            lines.append(f"| {item['name']} | `{item['key']}` | {item['category']} | {disabled} |")
    if report["regressed"]:
        lines.append("")
        lines.append("## Regressed")
        lines.append("")
        for item in report["regressed"]:
            lines.append(f"- {item['name']} (`{item['key']}`)")
    return "\n".join(lines) + "\n"


def cmd_snapshot(args: argparse.Namespace) -> int:
    data = fetch_challenges(args.target)
    payload = json.dumps(data, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    before = load_snapshot(Path(args.before))
    after = load_snapshot(Path(args.after))
    report = diff_snapshots(before, after)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_markdown(report), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Exact Juice Shop challenge coverage helper")
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot", help="Fetch /api/Challenges from a local Juice Shop target")
    snap.add_argument("--target", required=True, help="Juice Shop base URL, e.g. http://127.0.0.1:3000")
    snap.add_argument("--out", help="Write snapshot JSON to this path")
    snap.set_defaults(func=cmd_snapshot)

    diff = sub.add_parser("diff", help="Compare two challenge snapshots")
    diff.add_argument("--before", required=True, help="Snapshot before the scan")
    diff.add_argument("--after", required=True, help="Snapshot after the scan")
    diff.add_argument("--format", choices=("markdown", "json"), default="markdown")
    diff.set_defaults(func=cmd_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"juice_coverage: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
