import contextlib
import io
import unittest

import score


class ScoreCLITest(unittest.TestCase):
    def test_optional_scan_id(self):
        self.assertIsNone(score.parse_args([]).scan_id)
        self.assertEqual(score.parse_args(["42"]).scan_id, 42)

    def test_help_exits_cleanly(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            score.parse_args(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("scan_id", output.getvalue())


if __name__ == "__main__":
    unittest.main()
