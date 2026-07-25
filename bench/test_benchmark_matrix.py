import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchmark_matrix


def row(
    target: str,
    run_id: str,
    *,
    comparable: bool = True,
    coverage_status: str = "pass",
    coverage_total: int = 1,
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
        traffic=1,
        profiles=1,
        confirmed=0,
        confirmed_types={},
        retest_ready=0,
        average_proof_quality=0,
        followups=0,
        followup_status={},
        ai_calls=0,
        ai_tokens_in=0,
        ai_tokens_out=0,
        coverage_status=coverage_status,
        coverage_passed=1 if coverage_status == "pass" else 0,
        coverage_total=coverage_total,
        coverage_missing=[] if coverage_status == "pass" else ["sqli-lesson"],
        target_benchmark={},
        benchmark_ready=benchmark_matrix.benchmark_ready(comparable, coverage_status, coverage_total),
    )


def write_scorecard(
    root: Path,
    run_id: str,
    *,
    target: str,
    comparable: bool,
    quality: str | None = None,
    reasons: list[str] | None = None,
    confirmed: int = 0,
    confirmed_types: dict[str, int] | None = None,
    retest_ready: int = 0,
) -> Path:
    run_dir = root / run_id
    run_dir.mkdir(parents=True)
    scorecard_path = run_dir / "scorecard.json"
    scorecard_path.write_text(
        json.dumps(
            {
                "db": str(run_dir / "scan.db"),
                "scan": {
                    "target": f"https://{target}.test",
                    "status": "completed" if comparable else "interrupted",
                    "elapsed_seconds": 90,
                },
                "traffic": {"total": 12},
                "profiles": {"total": 4},
                "findings": {
                    "confirmed_count": confirmed,
                    "confirmed": [
                        {"vuln_type": vuln_type}
                        for vuln_type, count in (confirmed_types or {}).items()
                        for _ in range(count)
                    ],
                    "retest_ready_confirmed": retest_ready,
                    "average_proof_quality": 5.5 if confirmed else 0,
                },
                "followups": {"total": 0, "by_status": {}},
                "ai": {"calls": 3, "tokens_in": 100, "tokens_out": 40},
                "run_metadata": {"target": target},
                "benchmark_quality": {
                    "comparable": comparable,
                    "status": quality or ("comparable" if comparable else "partial"),
                    "reasons": reasons or [],
                },
            }
        ),
        encoding="utf-8",
    )
    return scorecard_path


def write_vulnerableapp_benchmark(root: Path, run_id: str) -> None:
    path = root / run_id / "vulnerableapp_benchmark.json"
    path.write_text(
        json.dumps(
            {
                "ground_truth": {"total": 162, "insecure": 145},
                "confirmed_findings": 17,
                "comparator_submittable": 17,
                "local": {
                    "matched": 5,
                    "expected": 145,
                    "coverage_percent": 3.45,
                    "by_family": {"file_upload": 5},
                },
                "submission": {
                    "raw": 17,
                    "unique": 6,
                    "duplicates": 11,
                    "matched": 5,
                    "expected": 145,
                    "unmatched": 1,
                    "unmatched_items": [
                        {
                            "path": "/UnrestrictedFileUpload/LEVEL_8",
                            "method": "POST",
                            "type": "UNRESTRICTED_FILE_UPLOAD",
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )


def write_juice_coverage(root: Path, run_id: str) -> None:
    path = root / run_id / "juice_coverage.json"
    path.write_text(
        json.dumps(
            {
                "kind": "juice",
                "total": 113,
                "solved": 53,
                "solved_percent": 46.9,
                "enabled_total": 109,
                "enabled_solved": 53,
                "enabled_solved_percent": 48.62,
                "solved_keys": ["scoreBoardChallenge"],
                "categories": {},
                "enabled_categories": {},
            }
        ),
        encoding="utf-8",
    )


class BenchmarkMatrixTest(unittest.TestCase):
    def test_missing_root_discovers_no_rows(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-matrix-test-") as tmp:
            root = Path(tmp) / "missing"

            self.assertEqual(benchmark_matrix.discover_scorecards(root), [])
            self.assertEqual(benchmark_matrix.collect_rows(root), [])

    def test_discovery_includes_scan_db_only_run_directories(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-matrix-test-") as tmp:
            root = Path(tmp)
            run_dir = root / "20260717-120000-dvwa"
            run_dir.mkdir(parents=True)
            (run_dir / "scan.db").write_bytes(b"")

            paths = benchmark_matrix.discover_scorecards(root)

            self.assertEqual(paths, [run_dir / "scorecard.json"])

    def test_latest_per_target_prefers_latest_run(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-matrix-test-") as tmp:
            root = Path(tmp)
            write_scorecard(root, "20260717-090000-vampi", target="vampi", comparable=True, confirmed=2)
            write_scorecard(root, "20260717-100000-vampi", target="vampi", comparable=True, confirmed=4)

            rows = benchmark_matrix.latest_per_target(benchmark_matrix.collect_rows(root))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].run_id, "20260717-100000-vampi")
            self.assertEqual(rows[0].confirmed, 4)

    def test_comparable_only_keeps_latest_comparable_when_newest_is_partial(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-matrix-test-") as tmp:
            root = Path(tmp)
            write_scorecard(root, "20260717-100000-juice", target="juice", comparable=True, confirmed=8)
            write_scorecard(
                root,
                "20260717-110000-juice",
                target="juice",
                comparable=False,
                reasons=["provider_failures:3"],
                confirmed=0,
            )

            rows = benchmark_matrix.latest_per_target(
                benchmark_matrix.collect_rows(root),
                comparable_only=True,
            )

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].run_id, "20260717-100000-juice")
            self.assertTrue(rows[0].comparable)
            self.assertEqual(rows[0].confirmed, 8)

    def test_benchmark_ready_only_keeps_latest_ready_when_newest_lacks_coverage(self):
        rows = [
            row("webgoat", "20260717-100000-webgoat", coverage_status="pass", coverage_total=8),
            row("webgoat", "20260717-110000-webgoat", coverage_status="partial", coverage_total=8),
        ]

        selected = benchmark_matrix.latest_per_target(rows, benchmark_ready_only=True)

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].run_id, "20260717-100000-webgoat")
        self.assertTrue(selected[0].benchmark_ready)

    def test_benchmark_ready_requires_comparable_scan_and_passing_coverage(self):
        self.assertTrue(benchmark_matrix.benchmark_ready(True, "pass", 3))
        self.assertTrue(benchmark_matrix.benchmark_ready(True, "unknown", 0))
        self.assertFalse(benchmark_matrix.benchmark_ready(False, "pass", 3))
        self.assertFalse(benchmark_matrix.benchmark_ready(True, "partial", 3))
        self.assertFalse(benchmark_matrix.benchmark_ready(True, "error", 0))

    def test_render_markdown_includes_quality_and_reason(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-matrix-test-") as tmp:
            root = Path(tmp)
            write_scorecard(
                root,
                "20260717-110000-juice",
                target="juice",
                comparable=False,
                reasons=["provider_failures:3"],
                confirmed=2,
                confirmed_types={"sqli": 1, "xss": 1},
            )

            rendered = benchmark_matrix.render_markdown(benchmark_matrix.collect_rows(root))

            self.assertIn("| juice | no | partial | unknown | — | interrupted |", rendered)
            self.assertIn("sqli:1, xss:1", rendered)
            self.assertIn("provider_failures:3", rendered)
            self.assertIn("Comparable rows: `0`", rendered)

    def test_render_markdown_includes_vulnerableapp_target_score(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-matrix-test-") as tmp:
            root = Path(tmp)
            run_id = "20260717-110000-vulnerableapp"
            write_scorecard(
                root,
                run_id,
                target="vulnerableapp",
                comparable=False,
                reasons=["llm_disabled"],
                confirmed=17,
            )
            write_vulnerableapp_benchmark(root, run_id)

            rows = benchmark_matrix.collect_rows(root)
            rendered = benchmark_matrix.render_markdown(rows)

            self.assertEqual(rows[0].target_benchmark["local_matched"], 5)
            self.assertIn("local 5/145 (3.45%)", rendered)
            self.assertIn("submit unique 6, dup 11, unmatched 1", rendered)
            self.assertIn("\"target_benchmark\"", json.dumps(benchmark_matrix.rows_to_json(rows)))

    def test_render_markdown_includes_juice_exact_challenge_score(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-matrix-test-") as tmp:
            root = Path(tmp)
            run_id = "20260718-001518-juice"
            write_scorecard(root, run_id, target="juice", comparable=True, confirmed=62)
            write_juice_coverage(root, run_id)

            rows = benchmark_matrix.collect_rows(root)
            rendered = benchmark_matrix.render_markdown(rows)

            self.assertEqual(rows[0].target_benchmark["solved"], 53)
            self.assertIn("solved 53/113 (46.9%)", rendered)
            self.assertIn("enabled 53/109 (48.62%)", rendered)
            self.assertIn("\"target_benchmark\"", json.dumps(benchmark_matrix.rows_to_json(rows)))


if __name__ == "__main__":
    unittest.main()
