#!/usr/bin/env python3
"""
Check whether a benchmark scan reached target-specific critical surfaces.

This is intentionally separate from vulnerability scoring. A run can find zero
confirmed issues and still be a useful precision benchmark, but only if it
actually exercised the relevant terrain for that target.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any


RUN_DIR_RE = re.compile(r"^\d{8}-\d{6}-(?P<target>.+)$")


@dataclass(frozen=True)
class CoverageRequirement:
    id: str
    label: str
    patterns: tuple[str, ...]


REQUIREMENTS: dict[str, tuple[CoverageRequirement, ...]] = {
    "crapi": (
        CoverageRequirement("identity", "Identity/auth APIs", ("/identity/",)),
        CoverageRequirement("workshop", "Workshop APIs", ("/workshop/",)),
        CoverageRequirement("community", "Community APIs", ("/community/",)),
        CoverageRequirement("shop", "Shop APIs", ("/shop/",)),
    ),
    "dvga": (
        CoverageRequirement("graphql", "GraphQL endpoint", ("/graphql",)),
        CoverageRequirement("introspection", "GraphQL introspection", ("__schema",)),
        CoverageRequirement("query-param", "GraphQL query traffic", ("query=",)),
    ),
    "dvwa": (
        CoverageRequirement("sqli", "SQL injection module", ("/vulnerabilities/sqli",)),
        CoverageRequirement("command-injection", "Command injection module", ("/vulnerabilities/exec",)),
        CoverageRequirement("brute", "Brute force/login module", ("/vulnerabilities/brute",)),
        CoverageRequirement("security-level", "Security level setup", ("/security.php",)),
    ),
    "vampi": (
        CoverageRequirement("openapi", "OpenAPI/Swagger document", ("/openapi", "/swagger")),
        CoverageRequirement("users", "Users API", ("/users",)),
        CoverageRequirement("books", "Books API", ("/books",)),
    ),
    "vulnerableapp": (
        CoverageRequirement("sitemap", "Vulnerability sitemap", ("/vulnerableapp/sitemap.xml",)),
        CoverageRequirement("scanner-index", "Scanner ground-truth index", ("/vulnerableapp/scanner",)),
        CoverageRequirement("benchmark-api", "Scanner comparator API", ("/vulnerableapp/scanner/benchmark",)),
        CoverageRequirement("auth", "Authentication vulnerability levels", ("/vulnerableapp/authenticationvulnerability/",)),
        CoverageRequirement("command-injection", "Command injection levels", ("/vulnerableapp/commandinjection/",)),
        CoverageRequirement("sqli", "SQL injection levels", ("/vulnerableapp/errorbasedsqlinjectionvulnerability/", "/vulnerableapp/unionbasedsqlinjectionvulnerability/")),
        CoverageRequirement("path-traversal", "Path traversal levels", ("/vulnerableapp/pathtraversal/",)),
        CoverageRequirement("ssrf", "SSRF levels", ("/vulnerableapp/ssrfvulnerability/",)),
        CoverageRequirement("idor", "IDOR levels", ("/vulnerableapp/idorvulnerability/",)),
        CoverageRequirement("jwt", "JWT levels", ("/vulnerableapp/jwtvulnerability/",)),
        CoverageRequirement("xss", "XSS levels", ("/vulnerableapp/xsswithhtmltaginjection/",)),
        CoverageRequirement("xxe", "XXE levels", ("/vulnerableapp/xxevulnerability/",)),
    ),
    "webgoat": (
        CoverageRequirement(
            "sqli-lesson",
            "SQL injection lesson",
            ("/webgoat/sqlinjection.lesson.lesson", "/service/lessonoverview.mvc/sqlinjection.lesson"),
        ),
        CoverageRequirement(
            "idor-lesson",
            "IDOR lesson",
            ("/webgoat/idor.lesson.lesson", "/service/lessonoverview.mvc/idor.lesson"),
        ),
        CoverageRequirement(
            "missing-function-ac",
            "Missing function access-control lesson",
            ("/webgoat/missingfunctionac.lesson.lesson", "/service/lessonoverview.mvc/missingfunctionac.lesson"),
        ),
        CoverageRequirement(
            "path-traversal-lesson",
            "Path traversal lesson",
            ("/webgoat/pathtraversal.lesson.lesson", "/service/lessonoverview.mvc/pathtraversal.lesson"),
        ),
        CoverageRequirement(
            "xxe-lesson",
            "XXE lesson",
            ("/webgoat/xxe.lesson.lesson", "/service/lessonoverview.mvc/xxe.lesson"),
        ),
        CoverageRequirement(
            "auth-bypass-lesson",
            "Auth bypass lesson",
            ("/webgoat/authbypass.lesson.lesson", "/service/lessonoverview.mvc/authbypass.lesson"),
        ),
        CoverageRequirement(
            "jwt-lesson",
            "JWT lesson",
            ("/webgoat/jwt.lesson.lesson", "/service/lessonoverview.mvc/jwt.lesson"),
        ),
        CoverageRequirement(
            "deserialization-lesson",
            "Insecure deserialization lesson",
            (
                "/webgoat/insecuredeserialization.lesson.lesson",
                "/service/lessonoverview.mvc/insecuredeserialization.lesson",
            ),
        ),
    ),
}


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.text_factory = lambda b: b.decode("utf-8", "replace")
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def latest_scan_id(conn: sqlite3.Connection) -> int | None:
    if not table_exists(conn, "scans"):
        return None
    row = conn.execute("SELECT MAX(id) AS id FROM scans").fetchone()
    return None if row is None or row["id"] is None else int(row["id"])


def read_run_metadata(db_path: Path) -> dict[str, Any]:
    meta_path = db_path.parent / "run_metadata.json"
    if not meta_path.exists():
        return {}
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def target_from_db(db_path: Path, explicit: str = "") -> str:
    if explicit:
        return explicit
    metadata = read_run_metadata(db_path)
    if metadata.get("target"):
        return str(metadata["target"])
    match = RUN_DIR_RE.match(db_path.parent.name)
    if match:
        return match.group("target")
    return ""


def collect_urls(db_path: Path, scan_id: int | None = None) -> list[str]:
    conn = connect(db_path)
    try:
        selected_scan_id = scan_id if scan_id is not None else latest_scan_id(conn)
        if selected_scan_id is None:
            return []
        urls: set[str] = set()
        for table in ("traffic", "page_profiles"):
            if not table_exists(conn, table):
                continue
            for row in conn.execute(
                f"SELECT COALESCE(url, '') AS url FROM {table} WHERE scan_id = ?",
                (selected_scan_id,),
            ):
                url = str(row["url"] or "").strip()
                if url:
                    urls.add(url)
        return sorted(urls)
    finally:
        conn.close()


def match_requirement(urls: list[str], requirement: CoverageRequirement) -> tuple[bool, list[str]]:
    lowered = [(url, url.lower()) for url in urls]
    matches: list[str] = []
    for pattern in requirement.patterns:
        needle = pattern.lower()
        for original, lower_url in lowered:
            if needle in lower_url:
                matches.append(original)
                break
    return bool(matches), matches


def evaluate_coverage(db_path: Path, target: str = "", scan_id: int | None = None) -> dict[str, Any]:
    target = target_from_db(db_path, target)
    urls = collect_urls(db_path, scan_id)
    requirements = REQUIREMENTS.get(target, ())
    checks: list[dict[str, Any]] = []
    for requirement in requirements:
        ok, matches = match_requirement(urls, requirement)
        checks.append(
            {
                "id": requirement.id,
                "label": requirement.label,
                "ok": ok,
                "patterns": list(requirement.patterns),
                "matches": matches[:5],
            }
        )
    passed = sum(1 for check in checks if check["ok"])
    total = len(checks)
    status = "unknown" if total == 0 else ("pass" if passed == total else "partial")
    return {
        "db": str(db_path),
        "target": target,
        "status": status,
        "passed": passed,
        "total": total,
        "score": 0 if total == 0 else round(passed / total, 3),
        "url_count": len(urls),
        "missing": [check["id"] for check in checks if not check["ok"]],
        "checks": checks,
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"## Benchmark coverage gate — {result.get('target') or 'unknown target'}",
        "",
        f"- Status: `{result['status']}`",
        f"- Coverage: `{result['passed']}/{result['total']}`",
        f"- URLs considered: `{result['url_count']}`",
        f"- Database: `{result['db']}`",
        "",
    ]
    checks = result.get("checks", [])
    if checks:
        lines += [
            "| Check | Status | Evidence |",
            "|---|---|---|",
        ]
        for check in checks:
            evidence = ", ".join(f"`{m}`" for m in check.get("matches", [])[:2])
            if not evidence:
                evidence = "—"
            lines.append(
                f"| {check['label']} | {'pass' if check['ok'] else 'missing'} | {evidence} |"
            )
    else:
        lines.append("_No coverage requirements are defined for this target._")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, type=Path, help="Path to scan.db")
    parser.add_argument("--target", default="", help="Override target name")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = evaluate_coverage(args.db, target=args.target, scan_id=args.scan_id)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
