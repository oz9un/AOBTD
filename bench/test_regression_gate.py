import unittest
import tempfile
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchmark_matrix
import regression_gate


DEFAULT_TYPES = {
    "crapi": {"info_disclosure": 1, "api_data_exposure": 2, "idor": 1},
    "dvga": {"graphql_data_exposure": 1, "graphql_introspection": 1, "attack_chain": 1},
    "dvwa": {"command_injection": 1, "sqli": 2, "attack_chain": 1},
    "juice": {"sqli": 2, "jwt_unsigned": 2, "path_traversal": 6, "xss_browser": 1},
    "vampi": {
        "debug_console_exposure": 1,
        "api_data_exposure": 2,
        "required_field_validation_bypass": 1,
    },
    "webgoat": {"sqli": 1, "xxe": 2},
    "vulnerableapp": {
        "CLIENT_SIDE_VULNERABLE_JWT": 9,
        "INSECURE_CONFIGURATION_JWT": 3,
        "SERVER_SIDE_VULNERABLE_JWT": 4,
        "clickjacking": 5,
        "command_injection": 5,
        "file_upload_size_bypass": 5,
        "file_upload_type_bypass": 5,
        "ldap_injection": 4,
        "open_redirect": 4,
        "path_traversal": 14,
        "persistent_xss": 5,
        "reflected_xss": 12,
        "sqli": 10,
    },
}


def row(
    target: str,
    run_id: str,
    *,
    ready: bool = True,
    comparable: bool = True,
    confirmed: int = 1,
    confirmed_types: dict[str, int] | None = None,
    retest_ready: int = 1,
    proof: float = 6.0,
) -> benchmark_matrix.MatrixRow:
    return benchmark_matrix.MatrixRow(
        target=target,
        run_id=run_id,
        db=f"/tmp/{run_id}/scan.db",
        quality="comparable" if comparable else "partial",
        comparable=comparable,
        reasons=[] if comparable else ["scan_status:interrupted"],
        scan_status="completed" if comparable else "interrupted",
        duration_seconds=60,
        traffic=10,
        profiles=3,
        confirmed=confirmed,
        confirmed_types=confirmed_types if confirmed_types is not None else (DEFAULT_TYPES.get(target, {"untyped": confirmed}) if confirmed else {}),
        retest_ready=retest_ready,
        average_proof_quality=proof,
        followups=0,
        followup_status={},
        ai_calls=1,
        ai_tokens_in=1,
        ai_tokens_out=1,
        coverage_status="pass" if ready else "partial",
        coverage_passed=1 if ready else 0,
        coverage_total=1,
        coverage_missing=[] if ready else ["coverage-gap"],
        target_benchmark={},
        benchmark_ready=ready and comparable,
    )


class RegressionGateTest(unittest.TestCase):
    def test_load_baselines_from_json_file(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-baseline-test-") as tmp:
            path = Path(tmp) / "baselines.json"
            path.write_text(
                json.dumps(
                    {
                        "custom": {
                            "min_confirmed": 2,
                            "min_retest_ready": 1,
                            "min_avg_proof": 4.5,
                        }
                    }
                ),
                encoding="utf-8",
            )

            baselines = regression_gate.load_baselines(path)

            self.assertEqual(
                baselines,
                {
                    "custom": {
                        "min_confirmed": 2,
                        "min_retest_ready": 1,
                        "min_avg_proof": 4.5,
                        "required_types": [],
                    }
                },
            )

    def test_load_baselines_rejects_missing_thresholds(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-baseline-test-") as tmp:
            path = Path(tmp) / "baselines.json"
            path.write_text(json.dumps({"custom": {"min_confirmed": 2}}), encoding="utf-8")

            with self.assertRaises(SystemExit):
                regression_gate.load_baselines(path)

    def test_passes_when_all_baselines_are_met(self):
        rows = [
            row("crapi", "20260717-1-crapi", confirmed=4, retest_ready=4),
            row("dvga", "20260717-1-dvga", confirmed=3, retest_ready=3),
            row("dvwa", "20260717-1-dvwa", confirmed=4, retest_ready=4, proof=5.5),
            row("juice", "20260717-1-juice", confirmed=62, retest_ready=62, proof=5.35),
            row("vampi", "20260717-1-vampi", confirmed=4, retest_ready=4),
            row("webgoat", "20260717-1-webgoat", confirmed=3, retest_ready=3),
            row("vulnerableapp", "20260717-1-vulnerableapp", confirmed=85, retest_ready=85, proof=5.26),
        ]

        result = regression_gate.evaluate_rows(rows)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["passed"], 7)

    def test_fails_when_signal_drops_below_baseline(self):
        rows = [
            row("crapi", "20260717-1-crapi", confirmed=0, retest_ready=0, proof=4.0),
            row("dvga", "20260717-1-dvga", confirmed=3, retest_ready=3),
            row("dvwa", "20260717-1-dvwa", confirmed=4, retest_ready=4),
            row("juice", "20260717-1-juice", confirmed=62, retest_ready=62, proof=5.35),
            row("vampi", "20260717-1-vampi", confirmed=4, retest_ready=4),
            row("webgoat", "20260717-1-webgoat", confirmed=3, retest_ready=3),
            row("vulnerableapp", "20260717-1-vulnerableapp", confirmed=85, retest_ready=85, proof=5.26),
        ]

        result = regression_gate.evaluate_rows(rows)

        self.assertEqual(result["status"], "fail")
        crapi = next(check for check in result["checks"] if check["target"] == "crapi")
        self.assertIn("confirmed:0<4", crapi["reason"])
        self.assertIn("retest_ready:0<4", crapi["reason"])
        self.assertIn("avg_proof:4.0<5.0", crapi["reason"])

    def test_fails_when_required_confirmed_type_is_missing(self):
        rows = [
            row("crapi", "20260717-1-crapi", confirmed=4, retest_ready=4),
            row("dvga", "20260717-1-dvga", confirmed=3, retest_ready=3),
            row("dvwa", "20260717-1-dvwa", confirmed=4, retest_ready=4, confirmed_types={"sqli": 2, "attack_chain": 1}),
            row("juice", "20260717-1-juice", confirmed=62, retest_ready=62, proof=5.35),
            row("vampi", "20260717-1-vampi", confirmed=4, retest_ready=4),
            row("webgoat", "20260717-1-webgoat", confirmed=3, retest_ready=3),
            row("vulnerableapp", "20260717-1-vulnerableapp", confirmed=85, retest_ready=85, proof=5.26),
        ]

        result = regression_gate.evaluate_rows(rows)

        self.assertEqual(result["status"], "fail")
        dvwa = next(check for check in result["checks"] if check["target"] == "dvwa")
        self.assertIn("missing_types:command_injection", dvwa["reason"])

    def test_latest_mode_fails_when_newest_row_is_not_ready(self):
        rows = [
            row("crapi", "20260717-1-crapi", confirmed=4, retest_ready=4),
            row("crapi", "20260717-2-crapi", ready=False, comparable=False, confirmed=0, retest_ready=0),
            row("dvga", "20260717-1-dvga", confirmed=3, retest_ready=3),
            row("dvwa", "20260717-1-dvwa", confirmed=4, retest_ready=4),
            row("juice", "20260717-1-juice", confirmed=62, retest_ready=62, proof=5.35),
            row("vampi", "20260717-1-vampi", confirmed=4, retest_ready=4),
            row("webgoat", "20260717-1-webgoat", confirmed=3, retest_ready=3),
            row("vulnerableapp", "20260717-1-vulnerableapp", confirmed=85, retest_ready=85, proof=5.26),
        ]

        latest_ready = regression_gate.evaluate_rows(rows, mode="latest-ready")
        latest = regression_gate.evaluate_rows(rows, mode="latest")

        self.assertEqual(latest_ready["status"], "pass")
        self.assertEqual(latest["status"], "fail")
        crapi = next(check for check in latest["checks"] if check["target"] == "crapi")
        self.assertIn("not_benchmark_ready", crapi["reason"])


if __name__ == "__main__":
    unittest.main()
