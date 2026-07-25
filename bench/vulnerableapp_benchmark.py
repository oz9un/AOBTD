#!/usr/bin/env python3
"""
OWASP VulnerableApp-specific benchmark helper.

VulnerableApp is unusually useful for DAST benchmarking because it exposes its
own ground-truth scanner index at /VulnerableApp/scanner and a comparator API at
/VulnerableApp/scanner/benchmark. This module keeps that target-specific signal
separate from the generic scorecard:

  - summarize the app's expected vulnerable surfaces
  - map AOBTD confirmed findings onto VulnerableApp paths/families
  - optionally submit normalized findings to the app's native comparator

The local matcher is intentionally conservative. It matches confirmed findings
only when both the target path and vulnerability family line up.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

VAPP_TYPE_FAMILY = {
    "ERROR_BASED_SQL_INJECTION": "sqli",
    "UNION_BASED_SQL_INJECTION": "sqli",
    "BLIND_SQL_INJECTION": "sqli",
    "COMMAND_INJECTION": "command_injection",
    "PATH_TRAVERSAL": "path_traversal",
    "SIMPLE_SSRF": "ssrf",
    "INSECURE_DIRECT_OBJECT_REFERENCE": "idor",
    "CLIENT_SIDE_VULNERABLE_JWT": "jwt",
    "SERVER_SIDE_VULNERABLE_JWT": "jwt",
    "INSECURE_CONFIGURATION_JWT": "jwt",
    "HEADER_INJECTION": "jwt",
    "REFLECTED_XSS": "xss",
    "PERSISTENT_XSS": "xss",
    "XXE": "xxe",
    "OPEN_REDIRECT_3XX_STATUS_CODE": "open_redirect",
    "LDAP_INJECTION": "ldap_injection",
    "CLICKJACKING": "clickjacking",
    "UNRESTRICTED_FILE_UPLOAD": "file_upload",
    "WEB_CACHE_POISONING": "cache_poisoning",
    "PLAINTEXT_PASSWORD_STORAGE": "weak_auth_storage",
    "WEAK_PASSWORD_HASHING": "weak_auth_storage",
    "USERNAME_ENUMERATION": "username_enumeration",
    "SESSION_FIXATION": "session_management",
    "PREDICTABLE_SESSION_ID": "session_management",
    "OBSCURED_PREDICTABLE_SESSION_ID": "session_management",
    "MISSING_LOGOUT_INVALIDATION": "session_management",
    "NO_LOGIN_RATE_LIMITING": "session_management",
    "INSECURE_CRYPTOGRAPHIC_STORAGE": "crypto",
    "USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM": "crypto",
    "WEAK_CRYPTOGRAPHIC_HASH": "crypto",
    "UNCONTROLLED_RESOURCE_CONSUMPTION": "dos",
    "DENIAL_OF_SERVICE": "dos",
}


@dataclass(frozen=True)
class GroundTruthItem:
    url: str
    path: str
    method: str
    variant: str
    vulnerability_type: str
    family: str


def normalize_type(value: str) -> str:
    value = value.strip().upper()
    value = re.sub(r"[^A-Z0-9]+", "_", value)
    return value.strip("_")


def vulnerableapp_relative_path(raw_url: str) -> str:
    parsed = urllib.parse.urlparse(raw_url)
    path = parsed.path or raw_url
    lower = path.lower()
    marker = "/vulnerableapp"
    idx = lower.find(marker)
    if idx >= 0:
        path = path[idx + len(marker) :]
    if not path:
        path = "/"
    path = "/" + path.lstrip("/")
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def scanner_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if not base.lower().endswith("/vulnerableapp"):
        base = base + "/VulnerableApp"
    return base + "/scanner"


def comparator_url(base_url: str) -> str:
    return scanner_url(base_url) + "/benchmark"


def parse_ground_truth(raw: list[dict[str, Any]]) -> list[GroundTruthItem]:
    items: list[GroundTruthItem] = []
    for entry in raw:
        url = str(entry.get("url") or "").strip()
        method = str(entry.get("method") or "GET").upper()
        variant = str(entry.get("variant") or "").upper()
        for vuln_type_raw in entry.get("vulnerabilityTypes") or []:
            vuln_type = normalize_type(str(vuln_type_raw))
            items.append(
                GroundTruthItem(
                    url=url,
                    path=vulnerableapp_relative_path(url),
                    method=method,
                    variant=variant,
                    vulnerability_type=vuln_type,
                    family=VAPP_TYPE_FAMILY.get(vuln_type, vuln_type.lower()),
                )
            )
    return items


def fetch_ground_truth(base_url: str, timeout: float = 15.0) -> list[GroundTruthItem]:
    req = urllib.request.Request(
        scanner_url(base_url),
        headers={"User-Agent": "AOBTD VulnerableApp benchmark"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = json.loads(resp.read().decode("utf-8", "replace"))
    if not isinstance(raw, list):
        raise SystemExit(f"VulnerableApp scanner index was not a list: {scanner_url(base_url)}")
    return parse_ground_truth(raw)


def summarize_ground_truth(items: list[GroundTruthItem]) -> dict[str, Any]:
    insecure = [item for item in items if item.variant != "SECURE"]
    return {
        "total": len(items),
        "insecure": len(insecure),
        "secure": len(items) - len(insecure),
        "by_type": dict(Counter(item.vulnerability_type for item in insecure)),
        "by_family": dict(Counter(item.family for item in insecure)),
    }


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.text_factory = lambda b: b.decode("utf-8", "replace")
    conn.row_factory = sqlite3.Row
    return conn


def latest_scan_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT MAX(id) AS id FROM scans").fetchone()
    return None if row is None or row["id"] is None else int(row["id"])


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def row_text(row: sqlite3.Row, key: str) -> str:
    try:
        value = row[key]
    except (KeyError, IndexError):
        return ""
    return "" if value is None else str(value)


def extract_method_path(endpoint_id: str, poc_request: str = "") -> tuple[str, str]:
    endpoint_id = endpoint_id.strip()
    first = endpoint_id.splitlines()[0].strip() if endpoint_id else ""
    if first:
        parts = first.split()
        if len(parts) >= 2 and parts[0].upper() in HTTP_METHODS:
            return parts[0].upper(), vulnerableapp_relative_path(parts[1])
        if first.startswith("http://") or first.startswith("https://") or first.startswith("/"):
            return "", vulnerableapp_relative_path(first)

    first_req = poc_request.splitlines()[0].strip() if poc_request else ""
    parts = first_req.split()
    if len(parts) >= 2 and parts[0].upper() in HTTP_METHODS:
        return parts[0].upper(), vulnerableapp_relative_path(parts[1])
    return "", ""


def infer_family(vuln_type: str, title: str = "") -> str:
    haystack = normalize_type(" ".join([vuln_type, title])).lower()
    if "command" in haystack and "injection" in haystack:
        return "command_injection"
    if "sql" in haystack or haystack in {"sqli", "sql_injection"}:
        return "sqli"
    if "path_traversal" in haystack or "directory_traversal" in haystack:
        return "path_traversal"
    if "ssrf" in haystack:
        return "ssrf"
    if "idor" in haystack or "object_reference" in haystack or "bola" in haystack:
        return "idor"
    if "jwt" in haystack:
        return "jwt"
    if "xss" in haystack or "cross_site_script" in haystack:
        return "xss"
    if "xxe" in haystack:
        return "xxe"
    if "open_redirect" in haystack or "redirect" in haystack:
        return "open_redirect"
    if "ldap" in haystack:
        return "ldap_injection"
    if "clickjack" in haystack:
        return "clickjacking"
    if "upload" in haystack:
        return "file_upload"
    return ""


def comparator_type_for_finding(family: str, path: str, vuln_type: str = "") -> str:
    normalized = normalize_type(vuln_type)
    if normalized in VAPP_TYPE_FAMILY:
        return normalized
    lower_path = path.lower()
    if family == "sqli":
        if "unionbased" in lower_path:
            return "UNION_BASED_SQL_INJECTION"
        if "blindsql" in lower_path:
            return "BLIND_SQL_INJECTION"
        return "ERROR_BASED_SQL_INJECTION"
    if family == "command_injection":
        return "COMMAND_INJECTION"
    if family == "path_traversal":
        return "PATH_TRAVERSAL"
    if family == "ssrf":
        return "SIMPLE_SSRF"
    if family == "idor":
        return "INSECURE_DIRECT_OBJECT_REFERENCE"
    if family == "jwt":
        return "SERVER_SIDE_VULNERABLE_JWT"
    if family == "xss":
        if "persistent" in lower_path:
            return "PERSISTENT_XSS"
        return "REFLECTED_XSS"
    if family == "xxe":
        return "XXE"
    if family == "open_redirect":
        return "OPEN_REDIRECT_3XX_STATUS_CODE"
    if family == "ldap_injection":
        return "LDAP_INJECTION"
    if family == "clickjacking":
        return "CLICKJACKING"
    if family == "file_upload":
        return "UNRESTRICTED_FILE_UPLOAD"
    return ""


def read_confirmed_findings(db_path: Path, scan_id: int | None = None) -> list[dict[str, Any]]:
    conn = connect(db_path)
    try:
        if not table_exists(conn, "findings"):
            return []
        selected_scan_id = scan_id if scan_id is not None else latest_scan_id(conn)
        if selected_scan_id is None:
            return []
        rows = conn.execute(
            """
            SELECT id, title, vuln_type, endpoint_id, poc_request, confidence
            FROM findings
            WHERE scan_id = ? AND lower(confidence) = 'confirmed'
            ORDER BY id
            """,
            (selected_scan_id,),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            method, path = extract_method_path(
                row_text(row, "endpoint_id"),
                row_text(row, "poc_request"),
            )
            family = infer_family(row_text(row, "vuln_type"), row_text(row, "title"))
            out.append(
                {
                    "id": int(row["id"]),
                    "title": row_text(row, "title"),
                    "vuln_type": row_text(row, "vuln_type"),
                    "endpoint": row_text(row, "endpoint_id"),
                    "method": method,
                    "path": path,
                    "family": family,
                }
            )
        return out
    finally:
        conn.close()


def compare_findings(
    ground_truth: list[GroundTruthItem],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    insecure = [item for item in ground_truth if item.variant != "SECURE"]
    by_key: dict[tuple[str, str, str], list[GroundTruthItem]] = {}
    family_by_truth_key: dict[tuple[str, str, str], str] = {}
    for item in insecure:
        by_key.setdefault((item.path.lower(), item.method, item.family), []).append(item)
        family_by_truth_key[(item.path, item.method, item.vulnerability_type)] = item.family

    matched_truth: set[tuple[str, str, str]] = set()
    matches: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for finding in findings:
        path = str(finding.get("path") or "").lower()
        method = str(finding.get("method") or "").upper()
        family = str(finding.get("family") or "")
        candidates = by_key.get((path, method, family), [])
        if not candidates and path and family:
            # Some AOBTD endpoint IDs omit method. Use path+family only then.
            candidates = [
                item
                for item in insecure
                if item.path.lower() == path and item.family == family
            ]
        if candidates:
            item = candidates[0]
            matched_truth.add((item.path, item.method, item.vulnerability_type))
            matches.append(
                {
                    "finding_id": finding.get("id"),
                    "path": item.path,
                    "method": item.method,
                    "family": item.family,
                    "type": item.vulnerability_type,
                    "title": finding.get("title"),
                }
            )
        else:
            unmatched.append(finding)

    expected_keys = {(item.path, item.method, item.vulnerability_type) for item in insecure}
    missed = sorted(expected_keys - matched_truth)
    total = len(expected_keys)
    matched = len(matched_truth)
    return {
        "expected": total,
        "matched": matched,
        "coverage_ratio": 0 if total == 0 else round(matched / total, 4),
        "coverage_percent": 0 if total == 0 else round(100 * matched / total, 2),
        "by_family": dict(Counter(family_by_truth_key[key] for key in matched_truth)),
        "matches": matches,
        "unmatched_findings": unmatched,
        "missed": [
            {"path": path, "method": method, "type": vuln_type}
            for path, method, vuln_type in missed
        ],
    }


def comparator_payload(
    findings: list[dict[str, Any]],
    base_url: str,
    tool_name: str = "aobtd",
) -> dict[str, Any]:
    base = base_url.rstrip("/")
    if not base.lower().endswith("/vulnerableapp"):
        base = base + "/VulnerableApp"
    out: list[dict[str, str]] = []
    for finding in findings:
        path = str(finding.get("path") or "")
        family = str(finding.get("family") or "")
        vuln_type = comparator_type_for_finding(family, path, str(finding.get("vuln_type") or ""))
        if not path or not vuln_type:
            continue
        out.append(
            {
                "url": urllib.parse.urljoin(base + "/", path.lstrip("/")),
                "type": vuln_type,
                "method": str(finding.get("method") or "GET").upper() or "GET",
            }
        )
    return {"tool": tool_name, "scanType": "DAST", "findings": out}


def payload_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    return (
        vulnerableapp_relative_path(str(finding.get("url") or "")),
        str(finding.get("method") or "GET").upper() or "GET",
        normalize_type(str(finding.get("type") or "")),
    )


def analyze_comparator_payload(
    ground_truth: list[GroundTruthItem],
    payload: dict[str, Any],
) -> dict[str, Any]:
    expected = {
        (item.path, item.method, item.vulnerability_type)
        for item in ground_truth
        if item.variant != "SECURE"
    }
    raw_items = [
        item for item in payload.get("findings", [])
        if isinstance(item, dict)
    ]
    submitted = [payload_key(item) for item in raw_items]
    submitted = [key for key in submitted if key[0] and key[2]]
    unique = set(submitted)
    matched = unique & expected
    unmatched = sorted(unique - expected)
    return {
        "raw": len(submitted),
        "unique": len(unique),
        "duplicates": len(submitted) - len(unique),
        "matched": len(matched),
        "expected": len(expected),
        "unmatched": len(unmatched),
        "unmatched_items": [
            {"path": path, "method": method, "type": vuln_type}
            for path, method, vuln_type in unmatched
        ],
    }


def post_comparator(base_url: str, payload: dict[str, Any], timeout: float = 20.0) -> dict[str, Any]:
    req = urllib.request.Request(
        comparator_url(base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "AOBTD VulnerableApp benchmark",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    if not isinstance(data, dict):
        raise SystemExit("VulnerableApp comparator response was not an object")
    return data


def evaluate_scan(
    db_path: Path,
    base_url: str,
    scan_id: int | None = None,
    *,
    post_native_comparator: bool = False,
) -> dict[str, Any]:
    ground_truth = fetch_ground_truth(base_url)
    findings = read_confirmed_findings(db_path, scan_id)
    local = compare_findings(ground_truth, findings)
    payload = comparator_payload(findings, base_url)
    submission = analyze_comparator_payload(ground_truth, payload)
    result: dict[str, Any] = {
        "db": str(db_path),
        "base_url": base_url,
        "ground_truth": summarize_ground_truth(ground_truth),
        "confirmed_findings": len(findings),
        "comparator_submittable": len(payload["findings"]),
        "submission": submission,
        "local": local,
    }
    if post_native_comparator:
        result["native_comparator"] = post_comparator(base_url, payload)
    return result


def render_markdown(result: dict[str, Any]) -> str:
    truth = result["ground_truth"]
    local = result["local"]
    lines = [
        "# VulnerableApp benchmark",
        "",
        f"- Database: `{result['db']}`",
        f"- Base URL: `{result['base_url']}`",
        f"- Ground truth: `{truth['insecure']}` insecure / `{truth['total']}` total entries",
        f"- Confirmed findings: `{result['confirmed_findings']}`",
        f"- Comparator-submittable findings: `{result['comparator_submittable']}`",
        f"- Local path+family coverage: `{local['matched']}/{local['expected']}` ({local['coverage_percent']}%)",
        f"- Unique comparator submissions: `{result.get('submission', {}).get('unique', 0)}` "
        f"(duplicates `{result.get('submission', {}).get('duplicates', 0)}`, "
        f"unmatched `{result.get('submission', {}).get('unmatched', 0)}`)",
        "",
        "| Family | Matched |",
        "|---|---:|",
    ]
    by_family = local.get("by_family") or {}
    if by_family:
        for family, count in sorted(by_family.items()):
            lines.append(f"| {family} | {count} |")
    else:
        lines.append("| — | 0 |")
    native = result.get("native_comparator")
    if isinstance(native, dict):
        lines += [
            "",
            "## Native comparator",
            "",
            f"- Detected: `{native.get('detected', 0)}`",
            f"- Missed: `{native.get('missed', 0)}`",
            f"- Unmatched: `{native.get('unmatched', 0)}`",
            f"- Coverage: `{native.get('coverage', 0)}`",
        ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:9091/VulnerableApp/")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--post-comparator", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = evaluate_scan(
        args.db,
        args.base_url,
        args.scan_id,
        post_native_comparator=args.post_comparator,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
