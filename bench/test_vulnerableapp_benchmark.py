import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vulnerableapp_benchmark


def sample_ground_truth() -> list[vulnerableapp_benchmark.GroundTruthItem]:
    return vulnerableapp_benchmark.parse_ground_truth(
        [
            {
                "url": "http://127.0.0.1:9091/VulnerableApp/CommandInjection/LEVEL_1",
                "variant": "UNSECURE",
                "method": "GET",
                "vulnerabilityTypes": ["COMMAND_INJECTION"],
            },
            {
                "url": "http://127.0.0.1:9091/VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1",
                "variant": "UNSECURE",
                "method": "GET",
                "vulnerabilityTypes": ["ERROR_BASED_SQL_INJECTION"],
            },
            {
                "url": "http://127.0.0.1:9091/VulnerableApp/XSSWithHtmlTagInjection/LEVEL_4",
                "variant": "SECURE",
                "method": "GET",
                "vulnerabilityTypes": ["REFLECTED_XSS"],
            },
        ]
    )


def make_scan_db() -> Path:
    root = Path(tempfile.mkdtemp(prefix="aobtd-vulnerableapp-test-"))
    db_path = root / "scan.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT);
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                title TEXT,
                vuln_type TEXT,
                endpoint_id TEXT,
                poc_request TEXT,
                confidence TEXT
            );
            """
        )
        conn.execute("INSERT INTO scans VALUES (1, 'http://127.0.0.1:9091/VulnerableApp/')")
        conn.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                1,
                "Command injection confirmed",
                "command_injection",
                "GET /VulnerableApp/CommandInjection/LEVEL_1",
                "",
                "confirmed",
            ),
        )
        conn.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                2,
                1,
                "SQL injection confirmed",
                "sqli",
                "",
                "GET /VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1 HTTP/1.1\nHost: target",
                "confirmed",
            ),
        )
        conn.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                3,
                1,
                "Weak header",
                "missing_header",
                "GET /VulnerableApp/",
                "",
                "possible",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return db_path


class VulnerableAppBenchmarkTest(unittest.TestCase):
    def test_relative_path_strips_vulnerableapp_prefix(self):
        self.assertEqual(
            vulnerableapp_benchmark.vulnerableapp_relative_path(
                "http://127.0.0.1:9091/VulnerableApp/CommandInjection/LEVEL_1"
            ),
            "/CommandInjection/LEVEL_1",
        )
        self.assertEqual(
            vulnerableapp_benchmark.vulnerableapp_relative_path("/VulnerableApp"),
            "/",
        )

    def test_ground_truth_summary_counts_only_insecure_by_family(self):
        summary = vulnerableapp_benchmark.summarize_ground_truth(sample_ground_truth())

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["insecure"], 2)
        self.assertEqual(summary["secure"], 1)
        self.assertEqual(summary["by_family"], {"command_injection": 1, "sqli": 1})

    def test_read_confirmed_findings_extracts_endpoint_and_poc_request_paths(self):
        findings = vulnerableapp_benchmark.read_confirmed_findings(make_scan_db())

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["method"], "GET")
        self.assertEqual(findings[0]["path"], "/CommandInjection/LEVEL_1")
        self.assertEqual(findings[0]["family"], "command_injection")
        self.assertEqual(findings[1]["path"], "/ErrorBasedSQLInjectionVulnerability/LEVEL_1")
        self.assertEqual(findings[1]["family"], "sqli")

    def test_compare_findings_matches_path_and_family_conservatively(self):
        findings = vulnerableapp_benchmark.read_confirmed_findings(make_scan_db())

        result = vulnerableapp_benchmark.compare_findings(sample_ground_truth(), findings)

        self.assertEqual(result["expected"], 2)
        self.assertEqual(result["matched"], 2)
        self.assertEqual(result["coverage_percent"], 100.0)
        self.assertEqual(result["by_family"], {"command_injection": 1, "sqli": 1})

    def test_family_counts_are_unique_ground_truth_matches_not_duplicate_findings(self):
        truth = vulnerableapp_benchmark.parse_ground_truth(
            [
                {
                    "url": "http://127.0.0.1:9091/VulnerableApp/UnrestrictedFileUpload/LEVEL_1",
                    "variant": "UNSECURE",
                    "method": "POST",
                    "vulnerabilityTypes": ["UNRESTRICTED_FILE_UPLOAD"],
                }
            ]
        )
        findings = [
            {
                "id": 1,
                "title": "Upload type bypass",
                "vuln_type": "file_upload_type_bypass",
                "method": "POST",
                "path": "/UnrestrictedFileUpload/LEVEL_1",
                "family": "file_upload",
            },
            {
                "id": 2,
                "title": "Upload size bypass",
                "vuln_type": "file_upload_size_bypass",
                "method": "POST",
                "path": "/UnrestrictedFileUpload/LEVEL_1",
                "family": "file_upload",
            },
        ]

        result = vulnerableapp_benchmark.compare_findings(truth, findings)

        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["by_family"], {"file_upload": 1})

    def test_comparator_payload_uses_exact_type_when_path_disambiguates_sqli(self):
        findings = vulnerableapp_benchmark.read_confirmed_findings(make_scan_db())

        payload = vulnerableapp_benchmark.comparator_payload(
            findings,
            "http://127.0.0.1:9091/VulnerableApp/",
        )

        self.assertEqual(payload["scanType"], "DAST")
        self.assertEqual(
            payload["findings"],
            [
                {
                    "url": "http://127.0.0.1:9091/VulnerableApp/CommandInjection/LEVEL_1",
                    "type": "COMMAND_INJECTION",
                    "method": "GET",
                },
                {
                    "url": "http://127.0.0.1:9091/VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1",
                    "type": "ERROR_BASED_SQL_INJECTION",
                    "method": "GET",
                },
            ],
        )

    def test_submission_analysis_counts_duplicates_and_unmatched_unique_items(self):
        truth = vulnerableapp_benchmark.parse_ground_truth(
            [
                {
                    "url": "http://127.0.0.1:9091/VulnerableApp/UnrestrictedFileUpload/LEVEL_1",
                    "variant": "UNSECURE",
                    "method": "POST",
                    "vulnerabilityTypes": ["UNRESTRICTED_FILE_UPLOAD"],
                },
                {
                    "url": "http://127.0.0.1:9091/VulnerableApp/UnrestrictedFileUpload/LEVEL_8",
                    "variant": "UNSECURE",
                    "method": "POST",
                    "vulnerabilityTypes": ["PATH_TRAVERSAL"],
                },
            ]
        )
        payload = {
            "tool": "aobtd",
            "scanType": "DAST",
            "findings": [
                {
                    "url": "http://127.0.0.1:9091/VulnerableApp/UnrestrictedFileUpload/LEVEL_1",
                    "method": "POST",
                    "type": "UNRESTRICTED_FILE_UPLOAD",
                },
                {
                    "url": "http://127.0.0.1:9091/VulnerableApp/UnrestrictedFileUpload/LEVEL_1",
                    "method": "POST",
                    "type": "UNRESTRICTED_FILE_UPLOAD",
                },
                {
                    "url": "http://127.0.0.1:9091/VulnerableApp/UnrestrictedFileUpload/LEVEL_8",
                    "method": "POST",
                    "type": "UNRESTRICTED_FILE_UPLOAD",
                },
            ],
        }

        analysis = vulnerableapp_benchmark.analyze_comparator_payload(truth, payload)

        self.assertEqual(analysis["raw"], 3)
        self.assertEqual(analysis["unique"], 2)
        self.assertEqual(analysis["duplicates"], 1)
        self.assertEqual(analysis["matched"], 1)
        self.assertEqual(analysis["unmatched"], 1)
        self.assertEqual(
            analysis["unmatched_items"],
            [
                {
                    "path": "/UnrestrictedFileUpload/LEVEL_8",
                    "method": "POST",
                    "type": "UNRESTRICTED_FILE_UPLOAD",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
