#!/usr/bin/env python3
"""
Map AOBTD findings + hypotheses against Juice Shop's 112 challenges to
produce a benchmark score. Runs against the live scan DB.

Usage:
    python bench/score.py [scan_id]       # specific scan
    python bench/score.py                  # latest scan

Output: a table of
  - category coverage (how many challenges in each Juice Shop category does
    our finding/hypothesis output plausibly address)
  - unmatched challenges (what we missed)
  - false positives (findings that don't map to any challenge)
"""
import json
import sqlite3
import sys
import re
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).parent.parent
DB = ROOT / "aobtd-output" / "scan.db"
CHALLENGES = ROOT / "bench" / "juice_challenges.json"


# ── Heuristic matchers: map our finding titles / hypothesis statements to
# Juice Shop challenge keys. Not exhaustive — good enough to see which
# categories we're covering and which we're missing entirely.
KEYWORD_TO_CHALLENGE = [
    # (pattern, matches list of challenge keys it plausibly satisfies)
    (r"password.*hash|hash.*leak",          ["passwordHashLeakChallenge"]),
    (r"idor|insecure direct object|sequential id|enumerable",
                                           ["accessLogDisclosureChallenge",
                                            "directoryListingChallenge",
                                            "changeProductChallenge",
                                            "viewBasketChallenge"]),
    (r"csrf|cross.site request forgery",   ["csrfChallenge"]),
    # Real XSS signals — tightened so that "Missing header: X-XSS-Protection"
    # doesn't inflate XSS coverage to 7/9 via a single header finding.
    # Requires explicit script/payload/reflected context.
    (r"cross.site scripting|"
     r"xss.*(?:payload|reflected|persist|dom|stored|attack|injection|bonus)|"
     r"(?:reflected|persist|dom|stored) xss|"
     r"<script|<iframe|javascript:alert|<svg onload",
                                           ["restfulXssChallenge",
                                            "persistedXssFeedbackChallenge",
                                            "persistedXssUserChallenge",
                                            "xssBonusPayloadChallenge",
                                            "domXssChallenge",
                                            "reflectedXssChallenge",
                                            "localXssChallenge"]),
    (r"sql.*injection|sqli",               ["loginAdminChallenge",
                                            "loginJimChallenge",
                                            "loginBenderChallenge",
                                            "unionSqlInjectionChallenge",
                                            "dbSchemaChallenge"]),
    (r"no.?sql",                           ["noSqlOrdersChallenge",
                                            "noSqlCommandChallenge"]),
    (r"open.?redirect|unvalidated redirect|attacker-controlled target|forwarded to attacker",
                                           ["redirectChallenge",
                                            "redirectCryptoCurrencyChallenge"]),
    # Weak/default credential acceptance probe
    (r"weak.*credential|default.*credential|admin123|trivially.?guessable",
                                           ["weakPasswordChallenge",
                                            "loginAdminChallenge",
                                            "oauthUserPasswordChallenge"]),
    # Unhandled-exception / stack trace disclosure probe
    (r"unhandled exception|stack trace|error handling|leaks.*stack|exception.*response",
                                           ["errorHandlingChallenge"]),
    # Improper input validation / out-of-range acceptance
    (r"improper input validation|out.?of.?range|range validation|"
     r"input_validation|rating=[0-9\-]|rating above max|rating zero",
                                           ["zeroStarsChallenge",
                                            "uiBoundValueChallenge",
                                            "negativeOrderChallenge",
                                            "persistedXssFeedbackChallenge"]),
    # CAPTCHA answer disclosure / anti-automation bypass
    (r"captcha.*leak|captcha.*answer|anti.?automation|captcha bypass|bypass.*captcha",
                                           ["captchaBypassChallenge",
                                            "resetPasswordJimChallenge"]),
    # Prometheus metrics / actuator disclosure
    (r"prometheus|/metrics|spring boot actuator|observability.*disclos|actuator.*expos",
                                           ["exposedMetricsChallenge"]),
    # Swagger / OpenAPI / API doc disclosure
    (r"swagger.?ui|/api-docs|api.*schema.*disclos|api spec disclos",
                                           ["misleadingProgressBarChallenge",
                                            "exposedCredentialsChallenge"]),
    # Null-byte / extension-filter bypass
    (r"null.?byte.*bypass|extension.?filter.?bypass|%00\.md|%2500\.md",
                                           ["fileAccessChallenge",
                                            "accessLogDisclosureChallenge",
                                            "directoryListingChallenge"]),
    # Permissive CORS on authenticated APIs
    (r"permissive cors|cors misconfigur|access-control-allow-origin.*\*|acao=\*",
                                           ["restfulXssChallenge",
                                            "securityPolicyChallenge"]),
    # Reflected input markers (potential reflected XSS sinks)
    (r"reflected input|reflected.?xss|unescaped marker|echo.*query",
                                           ["localXssChallenge",
                                            "reflectedXssChallenge"]),
    (r"directory.?list|expos.*path|file listing",
                                           ["directoryListingChallenge"]),
    (r"admin.*expos|admin.*unauth|admin.*/api/|admin endpoint",
                                           ["adminSectionChallenge",
                                            "scoreBoardChallenge"]),
    (r"xxe|xml external",                  ["xxeDosChallenge",
                                            "xxeFileDisclosureChallenge"]),
    (r"deserialization",                   ["ldapSearchChallenge"]),
    (r"path.?traversal|directory traversal|\.\./",
                                           ["directoryListingChallenge"]),
    (r"upload.*unrestricted|file upload|arbitrary upload",
                                           ["uploadTypeChallenge",
                                            "uploadSizeChallenge"]),
    (r"weak.*password|default.*cred|weak.*cred",
                                           ["weakPasswordChallenge",
                                            "loginAdminChallenge"]),
    # Login-bypass variants: email-quote-dashdash / OR-tautology / JWT-forgery
    (r"login bypass|auth bypass|bypass.*login|sqli.*login|login.*sqli|bypass.*auth",
                                           ["loginAdminChallenge",
                                            "loginJimChallenge",
                                            "loginBenderChallenge"]),
    (r"admin.*login|login.*admin",         ["loginAdminChallenge"]),
    # Proactive-probe hits
    (r"sensitive data.*exposure|exposure.*configuration|admin.*configuration",
                                           ["exposedCredentialsChallenge",
                                            "accessLogDisclosureChallenge",
                                            "adminSectionChallenge"]),
    (r"oauth.*credential|client.?id.*expos|authorizedredirects",
                                           ["exposedCredentialsChallenge",
                                            "weakPasswordChallenge"]),
    # /ftp directory listing + file exposure (Juice Shop specific)
    (r"/ftp(?:/|\b)",                      ["directoryListingChallenge"]),
    (r"/ftp/acquisitions",                 ["acquisitionsChallenge"]),
    (r"/ftp/incident|incident-support|\.kdbx|keepass",
                                           ["incidentReportKeybaseChallenge",
                                            "easterEggLevelOneChallenge"]),
    (r"/ftp/easter_egg|easter_egg",        ["easterEggLevelOneChallenge"]),
    (r"/ftp/coupons|coupons_\d{4}",        ["forgedCouponChallenge"]),
    (r"/ftp/legal",                        ["exposedMetricsChallenge"]),
    (r"/ftp/encrypt|encrypt\.pyc",         ["easterEggLevelOneChallenge"]),
    (r"/ftp/package\.json",                ["exposedCredentialsChallenge"]),
    (r"\.bak\b",                           ["exposedCredentialsChallenge"]),
    (r"/support/logs",                     ["accessLogDisclosureChallenge"]),
    (r"/swagger|openapi",                  ["misleadingProgressBarChallenge"]),
    (r"/\.env",                            ["exposedCredentialsChallenge"]),
    (r"/\.git",                            ["directoryListingChallenge"]),
    (r"jwt|bearer|weak.*signing",          ["jwtForgedChallenge",
                                            "jwtUnsignedChallenge"]),
    # Outdated/known-vulnerable component (e.g. Juice Shop self-disclosure)
    (r"outdated.*component|vulnerable.*component|juice shop \d|"
     r"known.?vulnerable|end.?of.?life|eol\b|application-version",
                                           ["knownVulnerableComponentChallenge"]),
    (r"rate limit|brute force|no rate",    ["resetPasswordBjoernChallenge"]),
    (r"information.?disclosure|reveal.*token|leaks api key",
                                           ["accessLogDisclosureChallenge",
                                            "dbSchemaChallenge"]),
    (r"cors.*permissive|access-control-allow-origin.*\*",
                                           ["restfulXssChallenge"]),
    (r"missing.*csp|content.security",     ["securityPolicyChallenge"]),
    (r"session|cookie flag|samesite",      ["weakPasswordChallenge"]),
]


def load_challenges():
    with open(CHALLENGES) as f:
        data = json.load(f)
    return data.get("data", [])


def load_scan_output(scan_id):
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    findings = c.execute(
        """SELECT id, title, severity, confidence, vuln_type, COALESCE(hypothesis_id,'') AS hyp
           FROM findings WHERE scan_id = ?""", (scan_id,)).fetchall()
    hyps = c.execute(
        """SELECT id, statement, confidence, status FROM hypotheses WHERE scan_id = ?""",
        (scan_id,)).fetchall()
    profiles = c.execute(
        """SELECT COUNT(*) AS n FROM page_profiles WHERE scan_id = ?""", (scan_id,)
    ).fetchone()["n"]
    traffic = c.execute(
        """SELECT COUNT(*) AS n FROM traffic WHERE scan_id = ?""", (scan_id,)
    ).fetchone()["n"]
    conn.close()
    return findings, hyps, profiles, traffic


def latest_scan_id():
    conn = sqlite3.connect(str(DB))
    row = conn.execute("SELECT MAX(id) FROM scans").fetchone()
    conn.close()
    return row[0]


def match_text_to_challenges(text):
    text = (text or "").lower()
    matched = set()
    for pattern, keys in KEYWORD_TO_CHALLENGE:
        if re.search(pattern, text):
            for k in keys:
                matched.add(k)
    return matched


def main():
    scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else latest_scan_id()
    if scan_id is None:
        print("No scans in DB")
        return 1

    chs = load_challenges()
    by_key = {c["key"]: c for c in chs}
    by_cat = defaultdict(list)
    for c in chs:
        by_cat[c["category"]].append(c)

    findings, hyps, profiles, traffic = load_scan_output(scan_id)

    print(f"=== Scan {scan_id} ===")
    print(f"traffic: {traffic}  profiles: {profiles}  "
          f"hypotheses: {len(hyps)}  findings: {len(findings)}")
    print(f"confirmed findings: {sum(1 for f in findings if f['confidence']=='confirmed')}")
    print()

    # Collect everything the scan said, match to challenge keys
    covered = set()
    for f in findings:
        text = f"{f['title']} {f['vuln_type']}"
        m = match_text_to_challenges(text)
        if f["confidence"] == "confirmed":
            covered |= m
    for h in hyps:
        if h["status"] in ("active", "confirmed"):
            covered |= match_text_to_challenges(h["statement"])

    print(f"=== Challenge coverage estimate: {len(covered)}/{len(chs)} ({len(covered)*100//len(chs)}%) ===")
    print()
    print("Coverage by category:")
    for cat, items in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        hit = sum(1 for c in items if c["key"] in covered)
        bar = "#" * hit + "." * (len(items) - hit)
        print(f"  {cat:40s}  {hit:2d}/{len(items):<2d}  {bar}")
    print()
    print("Confirmed findings in this scan:")
    confirmed = [f for f in findings if f["confidence"] == "confirmed"]
    if not confirmed:
        print("  (none)")
    for f in confirmed:
        hyp = f"  (hyp={f['hyp']})" if f["hyp"] else ""
        print(f"  [{f['severity']}] {f['title']}{hyp}")
    print()
    print("Active hypotheses:")
    for h in hyps:
        if h["status"] == "active":
            print(f"  [{h['confidence']:.2f}] {h['id']}: {h['statement'][:80]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
