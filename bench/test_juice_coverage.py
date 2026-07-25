import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import juice_coverage


def snapshot(items):
    return {"status": "success", "data": items}


class JuiceCoverageTest(unittest.TestCase):
    def test_diff_snapshots_counts_newly_solved_by_category(self):
        before = snapshot([
            {"key": "a", "name": "A", "category": "Access", "difficulty": 1, "solved": False},
            {"key": "b", "name": "B", "category": "Access", "difficulty": 2, "solved": True},
            {"key": "c", "name": "C", "category": "Injection", "difficulty": 3, "solved": False, "disabledEnv": "Docker"},
        ])
        after = snapshot([
            {"key": "a", "name": "A", "category": "Access", "difficulty": 1, "solved": True},
            {"key": "b", "name": "B", "category": "Access", "difficulty": 2, "solved": True},
            {"key": "c", "name": "C", "category": "Injection", "difficulty": 3, "solved": False, "disabledEnv": "Docker"},
        ])

        report = juice_coverage.diff_snapshots(before, after)

        self.assertEqual(report["total"], 3)
        self.assertEqual(report["before_solved"], 1)
        self.assertEqual(report["after_solved"], 2)
        self.assertEqual(report["enabled_total"], 2)
        self.assertEqual(report["before_enabled_solved"], 1)
        self.assertEqual(report["after_enabled_solved"], 2)
        self.assertEqual([item["key"] for item in report["newly_solved"]], ["a"])
        self.assertEqual([item["key"] for item in report["disabled_unsolved"]], ["c"])
        self.assertEqual(report["categories"]["Access"], {"total": 2, "before": 1, "after": 2, "new": 1})
        self.assertEqual(report["categories"]["Injection"], {"total": 1, "before": 0, "after": 0, "new": 0})
        self.assertEqual(report["enabled_categories"]["Access"], {"total": 2, "before": 1, "after": 2, "new": 1})

    def test_render_markdown_includes_exact_counts(self):
        report = {
            "total": 2,
            "before_solved": 0,
            "after_solved": 1,
            "enabled_total": 1,
            "before_enabled_solved": 0,
            "after_enabled_solved": 1,
            "newly_solved": [
                {"key": "loginAdminChallenge", "name": "Login Admin", "category": "Injection", "difficulty": 2}
            ],
            "regressed": [],
            "disabled_unsolved": [
                {"key": "rceChallenge", "name": "Blocked RCE DoS", "category": "Insecure Deserialization", "difficulty": 5, "disabledEnv": "Docker"}
            ],
            "categories": {
                "Injection": {"total": 2, "before": 0, "after": 1, "new": 1},
            },
        }

        rendered = juice_coverage.render_markdown(report)

        self.assertIn("After solved: `1/2`", rendered)
        self.assertIn("Enabled-env solved: `1/1`", rendered)
        self.assertIn("Login Admin", rendered)
        self.assertIn("| Injection | 2 | 0 | 1 | 1 |", rendered)
        self.assertIn("Blocked RCE DoS", rendered)
        self.assertIn("Docker", rendered)

    def test_summarize_snapshot_outputs_post_scan_target_score(self):
        summary = juice_coverage.summarize_snapshot(
            snapshot([
                {"key": "a", "name": "A", "category": "Access", "solved": True},
                {"key": "b", "name": "B", "category": "Access", "solved": False},
                {"key": "c", "name": "C", "category": "Injection", "solved": False, "disabledEnv": "Docker"},
            ])
        )

        self.assertEqual(summary["kind"], "juice")
        self.assertEqual(summary["solved"], 1)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["enabled_solved"], 1)
        self.assertEqual(summary["enabled_total"], 2)
        self.assertEqual(summary["categories"]["Access"], {"total": 2, "solved": 1})
        self.assertEqual(summary["enabled_categories"]["Access"], {"total": 2, "solved": 1})
        self.assertNotIn("Injection", summary["enabled_categories"])

        rendered = juice_coverage.render_summary(summary)
        self.assertIn("Solved challenges: `1/3`", rendered)
        self.assertIn("Enabled-env solved: `1/2`", rendered)


if __name__ == "__main__":
    unittest.main()
