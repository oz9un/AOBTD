import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coverage_gate


def make_coverage_db(urls: list[str], target: str = "webgoat") -> Path:
    root = Path(tempfile.mkdtemp(prefix=f"20260717-120000-{target}-"))
    db_path = root / "scan.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT);
            CREATE TABLE traffic (id INTEGER PRIMARY KEY, scan_id INTEGER, url TEXT);
            CREATE TABLE page_profiles (id TEXT, scan_id INTEGER, url TEXT);
            """
        )
        conn.execute("INSERT INTO scans VALUES (1, 'http://127.0.0.1')")
        for i, url in enumerate(urls, 1):
            conn.execute("INSERT INTO traffic VALUES (?, 1, ?)", (i, url))
        conn.commit()
    finally:
        conn.close()
    (root / "run_metadata.json").write_text(f'{{"target": "{target}"}}', encoding="utf-8")
    return db_path


class CoverageGateTest(unittest.TestCase):
    def test_webgoat_reports_missing_lesson_surfaces(self):
        db_path = make_coverage_db(
            [
                "http://127.0.0.1:8085/WebGoat/SqlInjection.lesson.lesson",
                "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/PathTraversal.lesson",
            ]
        )

        result = coverage_gate.evaluate_coverage(db_path)

        self.assertEqual(result["target"], "webgoat")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["passed"], 2)
        self.assertEqual(result["total"], 8)
        self.assertIn("idor-lesson", result["missing"])

    def test_unknown_target_is_non_blocking(self):
        db_path = make_coverage_db([], target="unknown")

        result = coverage_gate.evaluate_coverage(db_path)

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["passed"], 0)
        self.assertEqual(result["total"], 0)

    def test_vulnerableapp_requires_scanner_and_core_vuln_families(self):
        db_path = make_coverage_db(
            [
                "http://127.0.0.1:9091/VulnerableApp/sitemap.xml",
                "http://127.0.0.1:9091/VulnerableApp/scanner",
                "http://127.0.0.1:9091/VulnerableApp/scanner/benchmark",
                "http://127.0.0.1:9091/VulnerableApp/AuthenticationVulnerability/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/CommandInjection/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/UnionBasedSQLInjectionVulnerability/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/PathTraversal/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/SSRFVulnerability/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/IDORVulnerability/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/JWTVulnerability/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/XSSWithHtmlTagInjection/LEVEL_1",
                "http://127.0.0.1:9091/VulnerableApp/XXEVulnerability/LEVEL_1",
            ],
            target="vulnerableapp",
        )

        result = coverage_gate.evaluate_coverage(db_path)

        self.assertEqual(result["target"], "vulnerableapp")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["passed"], 12)
        self.assertEqual(result["total"], 12)

    def test_markdown_includes_missing_status(self):
        db_path = make_coverage_db(["http://127.0.0.1:5013/graphql"], target="dvga")

        rendered = coverage_gate.render_markdown(coverage_gate.evaluate_coverage(db_path))

        self.assertIn("Benchmark coverage gate", rendered)
        self.assertIn("| GraphQL endpoint | pass |", rendered)
        self.assertIn("| GraphQL introspection | missing |", rendered)


if __name__ == "__main__":
    unittest.main()
