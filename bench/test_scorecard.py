import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scorecard


def make_scorecard_db() -> Path:
    db_path = Path(tempfile.mkdtemp(prefix="aobtd-scorecard-test-")) / "scan.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY,
                target TEXT,
                started_at TEXT,
                finished_at TEXT,
                status TEXT,
                config_json TEXT
            );
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                title TEXT,
                description TEXT,
                severity TEXT,
                confidence TEXT,
                vuln_type TEXT,
                endpoint_id TEXT,
                param_name TEXT,
                payload TEXT,
                poc_request TEXT,
                poc_response TEXT,
                steps_to_reproduce TEXT,
                evidence TEXT
            );
            CREATE TABLE follow_ups (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                action TEXT,
                status TEXT
            );
            CREATE TABLE ai_log (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                agent TEXT,
                action TEXT,
                model_id TEXT,
                tokens_in INTEGER,
                tokens_out INTEGER,
                duration_ms INTEGER,
                cost_ucents INTEGER
            );
            """
        )
        conn.execute(
            "INSERT INTO scans VALUES (1, 'https://target.test', '2026-07-17 10:00:00', '2026-07-17 10:01:00', 'completed', '{}')"
        )
        conn.commit()
    finally:
        conn.close()
    return db_path


class ScorecardProofQualityTest(unittest.TestCase):
    def test_attack_chain_uses_composite_proof_quality(self):
        db_path = make_scorecard_db()
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                """
                INSERT INTO findings (
                    id, scan_id, title, description, severity, confidence, vuln_type,
                    endpoint_id, payload, poc_request, poc_response, steps_to_reproduce, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    1,
                    1,
                    "Attack chain",
                    "ChainReasoner composed a multi-step attack chain combining confirmed findings.\nRationale: introspection plus data exposure",
                    "info",
                    "confirmed",
                    "attack_chain",
                    "https://target.test/graphql",
                    "introspection plus data exposure",
                    "",
                    "",
                    "",
                    "Chain composed from confirmed findings by ChainReasoner.\nSteps:\n  1. enumerate schema\n  2. query sensitive fields",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        summary = scorecard.summarize_scan(db_path)
        quality = summary["findings"]["confirmed"][0]["proof_quality"]
        self.assertEqual(quality["score"], 6)
        self.assertEqual(quality["max"], 6)
        self.assertEqual(quality["missing"], [])
        self.assertEqual(summary["findings"]["retest_ready_confirmed"], 1)

    def test_regular_finding_still_requires_request_response(self):
        db_path = make_scorecard_db()
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                """
                INSERT INTO findings (
                    id, scan_id, title, description, severity, confidence, vuln_type,
                    endpoint_id, payload, poc_request, poc_response, steps_to_reproduce, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    1,
                    1,
                    "Sensitive data exposure",
                    "GET /api/users leaks data",
                    "high",
                    "confirmed",
                    "api_data_exposure",
                    "GET /api/users",
                    "",
                    "",
                    "",
                    "1. GET /api/users",
                    "response included email",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        summary = scorecard.summarize_scan(db_path)
        quality = summary["findings"]["confirmed"][0]["proof_quality"]
        self.assertIn("request", quality["missing"])
        self.assertIn("response", quality["missing"])
        self.assertLess(quality["score"], quality["max"])

    def test_benchmark_quality_marks_provider_failed_run_partial(self):
        db_path = make_scorecard_db()
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("UPDATE scans SET status = 'interrupted', finished_at = NULL WHERE id = 1")
            conn.execute(
                "INSERT INTO follow_ups (scan_id, action, status) VALUES (1, 'probe_param', 'pending')"
            )
            conn.commit()
        finally:
            conn.close()
        (db_path.parent / "run_metadata.json").write_text(
            """
            {
              "exit_code": 86,
              "terminated_reason": "provider_resource_exhausted",
              "log_health": {"provider_failures": 2}
            }
            """,
            encoding="utf-8",
        )

        summary = scorecard.summarize_scan(db_path)
        quality = summary["benchmark_quality"]
        self.assertFalse(quality["comparable"])
        self.assertEqual(quality["status"], "partial")
        self.assertIn("scan_status:interrupted", quality["reasons"])
        self.assertIn("missing_finished_at", quality["reasons"])
        self.assertIn("followups_not_drained:1", quality["reasons"])
        self.assertIn("process_exit_code:86", quality["reasons"])
        self.assertIn("terminated:provider_resource_exhausted", quality["reasons"])
        self.assertIn("provider_failures:2", quality["reasons"])

    def test_benchmark_quality_marks_no_llm_run_partial(self):
        db_path = make_scorecard_db()
        (db_path.parent / "run_metadata.json").write_text(
            """
            {
              "exit_code": 0,
              "scan_config": {"llm": "none", "max_pages": 20}
            }
            """,
            encoding="utf-8",
        )

        summary = scorecard.summarize_scan(db_path)
        quality = summary["benchmark_quality"]

        self.assertFalse(quality["comparable"])
        self.assertEqual(quality["status"], "partial")
        self.assertIn("llm_disabled", quality["reasons"])


if __name__ == "__main__":
    unittest.main()
