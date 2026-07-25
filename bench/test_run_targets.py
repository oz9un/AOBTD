import argparse
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_targets
import benchmark_matrix


class PreflightHandler(BaseHTTPRequestHandler):
    status_code = 200
    response_body = {"choices": [{"message": {"content": "OK"}}]}
    captured_body = {}
    captured_auth = ""

    def do_POST(self):  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        type(self).captured_body = json.loads(body.decode("utf-8"))
        type(self).captured_auth = self.headers.get("Authorization", "")
        self.send_response(type(self).status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(type(self).response_body).encode("utf-8"))

    def log_message(self, *_args):
        return


class PreflightServer:
    def __init__(self, status_code=200, response_body=None):
        PreflightHandler.status_code = status_code
        PreflightHandler.response_body = response_body or {"choices": [{"message": {"content": "OK"}}]}
        PreflightHandler.captured_body = {}
        PreflightHandler.captured_auth = ""
        self.server = HTTPServer(("127.0.0.1", 0), PreflightHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


def matrix_row(target: str, run_id: str, *, comparable: bool, ready: bool) -> benchmark_matrix.MatrixRow:
    coverage_status = "pass" if ready else "partial"
    return benchmark_matrix.MatrixRow(
        target=target,
        run_id=run_id,
        db=f"/tmp/{run_id}/scan.db",
        quality="comparable" if comparable else "partial",
        comparable=comparable,
        reasons=[],
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
        coverage_passed=1 if ready else 0,
        coverage_total=1,
        coverage_missing=[] if ready else ["coverage-gap"],
        target_benchmark={},
        benchmark_ready=ready,
    )


class RunTargetsTest(unittest.TestCase):
    def test_webgoat_seeds_real_lesson_surfaces_without_payloads(self):
        target = run_targets.TARGETS["webgoat"]
        seeds = target.seed_urls

        self.assertIn("http://127.0.0.1:8085/WebGoat/SqlInjection.lesson.lesson", seeds)
        self.assertIn("http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/SqlInjection.lesson", seeds)
        self.assertIn("http://127.0.0.1:8085/WebGoat/IDOR.lesson.lesson", seeds)
        self.assertIn("http://127.0.0.1:8085/WebGoat/PathTraversal.lesson.lesson", seeds)
        self.assertIn("http://127.0.0.1:8085/WebGoat/XXE.lesson.lesson", seeds)
        self.assertIn("http://127.0.0.1:8085/WebGoat/JWT.lesson.lesson", seeds)

        for seed in seeds:
            parsed = urlparse(seed)
            self.assertEqual(parsed.scheme, "http")
            self.assertEqual(parsed.netloc, "127.0.0.1:8085")
            self.assertFalse(parsed.query, f"seed should not pre-fill params/payloads: {seed}")
            self.assertNotIn("attack", parsed.path.lower(), f"seed should target lesson surfaces, not attack answers: {seed}")
            self.assertNotIn("assignment", parsed.path.lower(), f"seed should target lesson surfaces, not assignment answers: {seed}")

    def test_vulnerableapp_target_uses_ground_truth_surfaces_without_payloads(self):
        target = run_targets.TARGETS["vulnerableapp"]
        seeds = target.seed_urls

        self.assertEqual(target.image, "sasanlabs/owasp-vulnerableapp:latest")
        self.assertEqual(target.target_url, "http://127.0.0.1:9091/VulnerableApp/")
        self.assertIn("http://127.0.0.1:9091/VulnerableApp/sitemap.xml", seeds)
        self.assertIn("http://127.0.0.1:9091/VulnerableApp/scanner", seeds)
        self.assertIn("http://127.0.0.1:9091/VulnerableApp/scanner/benchmark", seeds)
        self.assertIn("http://127.0.0.1:9091/VulnerableApp/CommandInjection/LEVEL_1", seeds)
        self.assertIn("http://127.0.0.1:9091/VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1", seeds)
        self.assertIn("http://127.0.0.1:9091/VulnerableApp/XXEVulnerability/LEVEL_1", seeds)
        for seed in seeds:
            parsed = urlparse(seed)
            self.assertEqual(parsed.scheme, "http")
            self.assertEqual(parsed.netloc, "127.0.0.1:9091")
            self.assertFalse(parsed.query, f"seed should identify a surface, not provide payload params: {seed}")
            self.assertNotIn("payload", seed.lower(), f"seed should not carry exploit answers: {seed}")

    def test_crapi_target_uses_api_login_without_exploit_payloads(self):
        target = run_targets.TARGETS["crapi"]

        self.assertEqual(target.login_api_url, "http://127.0.0.1:8888/identity/api/auth/login")
        self.assertEqual(target.login_user, "aobtd-bench@example.com")
        self.assertEqual(target.login_pass, "Password1!")
        self.assertIn("http://127.0.0.1:8888/identity/api/v2/vehicle/vehicles", target.seed_urls)
        self.assertIn("http://127.0.0.1:8888/workshop/api/mechanic/receive_report", target.seed_urls)
        self.assertIn("http://127.0.0.1:8888/workshop/api/shop/orders/1", target.seed_urls)
        self.assertIn("http://127.0.0.1:8888/workshop/api/shop/orders/2", target.seed_urls)
        self.assertIn("http://127.0.0.1:8888/workshop/api/shop/orders/3", target.seed_urls)
        for seed in target.seed_urls:
            parsed = urlparse(seed)
            self.assertEqual(parsed.scheme, "http")
            self.assertEqual(parsed.netloc, "127.0.0.1:8888")
            self.assertFalse(parsed.query, f"seed should identify API terrain, not provide payloads: {seed}")

    def test_select_matrix_rows_prefers_ready_mode(self):
        rows = [
            matrix_row("webgoat", "20260717-100000-webgoat", comparable=True, ready=True),
            matrix_row("webgoat", "20260717-110000-webgoat", comparable=True, ready=False),
            matrix_row("juice", "20260717-110000-juice", comparable=False, ready=False),
        ]

        ready = run_targets.select_matrix_rows(rows, "ready")
        comparable = run_targets.select_matrix_rows(rows, "comparable")
        raw = run_targets.select_matrix_rows(rows, "raw")

        self.assertEqual([(r.target, r.run_id) for r in ready], [("webgoat", "20260717-100000-webgoat")])
        self.assertEqual([(r.target, r.run_id) for r in comparable], [("webgoat", "20260717-110000-webgoat")])
        self.assertEqual(
            [(r.target, r.run_id) for r in raw],
            [("juice", "20260717-110000-juice"), ("webgoat", "20260717-110000-webgoat")],
        )

    def test_scan_command_passes_llm_token_budgets(self):
        args = argparse.Namespace(
            proxy_port=8089,
            max_pages=70,
            max_depth=8,
            testing_authority="full_control",
            budget=0,
            llm_input_budget=80000,
            llm_output_budget=30000,
            strategist_period=0,
            llm="openai-compatible",
            model="MiniMax-M2.7-highspeed",
            llm_url="https://api.minimax.io/v1",
            reasoning_model="",
            analysis_endpoint_limit=0,
        )

        cmd = run_targets.scan_command(
            Path("/tmp/aobtd-bench"),
            run_targets.TARGETS["vulnerableapp"],
            Path("/tmp/aobtd-run"),
            args,
        )

        self.assertEqual(cmd[cmd.index("--llm-input-budget") + 1], "80000")
        self.assertEqual(cmd[cmd.index("--llm-output-budget") + 1], "30000")

    def test_scan_command_passes_target_analysis_endpoint_limit(self):
        args = argparse.Namespace(
            proxy_port=8089,
            max_pages=70,
            max_depth=8,
            testing_authority="full_control",
            budget=0,
            llm_input_budget=80000,
            llm_output_budget=30000,
            strategist_period=0,
            llm="openai-compatible",
            model="MiniMax-M2.7-highspeed",
            llm_url="https://api.minimax.io/v1",
            reasoning_model="",
            analysis_endpoint_limit=0,
        )

        cmd = run_targets.scan_command(
            Path("/tmp/aobtd-bench"),
            run_targets.TARGETS["dvwa"],
            Path("/tmp/aobtd-run"),
            args,
        )

        self.assertEqual(cmd[cmd.index("--analysis-endpoint-limit") + 1], "18")

    def test_scan_command_does_not_relogin_when_session_cookie_prepared(self):
        args = argparse.Namespace(
            proxy_port=8089,
            max_pages=70,
            max_depth=8,
            testing_authority="full_control",
            budget=0,
            llm_input_budget=80000,
            llm_output_budget=30000,
            strategist_period=0,
            llm="openai-compatible",
            model="MiniMax-M2.7-highspeed",
            llm_url="https://api.minimax.io/v1",
            reasoning_model="",
            analysis_endpoint_limit=0,
        )
        target = run_targets.Target(
            name="dvwa-test",
            kind="compose",
            target_url="http://127.0.0.1:4280/index.php",
            health_url="http://127.0.0.1:4280/login.php",
            login_url="http://127.0.0.1:4280/login.php",
            login_user="admin",
            login_pass="password",
            session_cookie="security=low; PHPSESSID=abc",
        )

        cmd = run_targets.scan_command(
            Path("/tmp/aobtd-bench"),
            target,
            Path("/tmp/aobtd-run"),
            args,
        )

        self.assertIn("--session-cookie", cmd)
        self.assertEqual(cmd[cmd.index("--session-cookie") + 1], "security=low; PHPSESSID=abc")
        self.assertNotIn("--login-url", cmd)
        self.assertNotIn("--login-user", cmd)
        self.assertNotIn("--login-pass", cmd)

    def test_scan_command_passes_crapi_api_login(self):
        args = argparse.Namespace(
            proxy_port=8089,
            max_pages=70,
            max_depth=8,
            testing_authority="full_control",
            budget=0,
            llm_input_budget=80000,
            llm_output_budget=30000,
            strategist_period=0,
            llm="openai-compatible",
            model="MiniMax-M2.7-highspeed",
            llm_url="https://api.minimax.io/v1",
            reasoning_model="",
            analysis_endpoint_limit=0,
        )

        cmd = run_targets.scan_command(
            Path("/tmp/aobtd-bench"),
            run_targets.TARGETS["crapi"],
            Path("/tmp/aobtd-run"),
            args,
        )

        self.assertEqual(cmd[cmd.index("--login-api-url") + 1], "http://127.0.0.1:8888/identity/api/auth/login")
        self.assertEqual(cmd[cmd.index("--login-user") + 1], "aobtd-bench@example.com")
        self.assertEqual(cmd[cmd.index("--login-pass") + 1], "Password1!")

    def test_provider_failure_reason_ignores_application_rate_limit_findings(self):
        self.assertEqual(
            run_targets.provider_failure_reason(
                "  [info/possible] No rate limiting observed but read-only endpoint with no attack surface"
            ),
            "",
        )
        self.assertEqual(
            run_targets.provider_failure_reason(
                "finding: endpoint appears to have no rate limit on password reset attempts"
            ),
            "",
        )

    def test_provider_failure_reason_detects_provider_rate_limit_context(self):
        self.assertEqual(
            run_targets.provider_failure_reason("LLM provider request failed: rate limit exceeded"),
            "provider_rate_limited",
        )
        self.assertEqual(
            run_targets.provider_failure_reason("api error 429: too many requests"),
            "provider_rate_limited",
        )

    def test_preflight_llm_success_uses_minimal_glm_payload(self):
        with PreflightServer() as url:
            args = argparse.Namespace(
                llm="openai-compatible",
                llm_url=url,
                model="glm-5.2",
                preflight_timeout=5,
            )

            ok, detail = run_targets.preflight_llm(args)

        self.assertTrue(ok)
        self.assertEqual(detail, "ok")
        self.assertEqual(PreflightHandler.captured_body["model"], "glm-5.2")
        self.assertEqual(PreflightHandler.captured_body["max_tokens"], 2)
        self.assertEqual(PreflightHandler.captured_body["thinking"], {"type": "disabled"})
        self.assertNotIn("Bearer", PreflightHandler.captured_auth)

    def test_preflight_llm_classifies_provider_resource_exhaustion(self):
        body = {
            "error": {
                "code": "1113",
                "message": "Insufficient balance or no resource package. Please recharge.",
            }
        }
        with PreflightServer(status_code=429, response_body=body) as url:
            args = argparse.Namespace(
                llm="openai-compatible",
                llm_url=url,
                model="glm-5.2",
                preflight_timeout=5,
            )

            ok, detail = run_targets.preflight_llm(args)

        self.assertFalse(ok)
        self.assertEqual(detail, "provider_resource_exhausted")

    def test_resolve_llm_api_key_prefers_minimax_for_minimax_compatible_config(self):
        names = ("AOBTD_LLM_KEY", "ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY", "MINIMAX_API_KEY")
        old_values = {name: os.environ.get(name) for name in names}
        try:
            for name in names:
                os.environ.pop(name, None)
            os.environ["ZAI_API_KEY"] = "zai-key"
            os.environ["MINIMAX_API_KEY"] = "minimax-key"

            self.assertEqual(
                run_targets.resolve_llm_api_key(
                    "openai-compatible",
                    "https://api.minimax.io/v1",
                    "MiniMax-M2.7-highspeed",
                ),
                "minimax-key",
            )
            self.assertEqual(
                run_targets.resolve_llm_api_key(
                    "openai-compatible",
                    "https://api.z.ai/api/coding/paas/v4",
                    "glm-4.6",
                ),
                "zai-key",
            )
        finally:
            for name, value in old_values.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_load_dotenv_local_preserves_existing_env(self):
        with tempfile.TemporaryDirectory(prefix="aobtd-dotenv-test-") as tmp:
            path = Path(tmp) / ".env.local"
            path.write_text(
                "ZAI_API_KEY=from-file\nexport GLM_API_KEY='glm-from-file'\n",
                encoding="utf-8",
            )
            old_zai = os.environ.get("ZAI_API_KEY")
            old_glm = os.environ.get("GLM_API_KEY")
            try:
                os.environ["ZAI_API_KEY"] = "already-set"
                os.environ.pop("GLM_API_KEY", None)

                run_targets.load_dotenv_local(path)

                self.assertEqual(os.environ.get("ZAI_API_KEY"), "already-set")
                self.assertEqual(os.environ.get("GLM_API_KEY"), "glm-from-file")
            finally:
                if old_zai is None:
                    os.environ.pop("ZAI_API_KEY", None)
                else:
                    os.environ["ZAI_API_KEY"] = old_zai
                if old_glm is None:
                    os.environ.pop("GLM_API_KEY", None)
                else:
                    os.environ["GLM_API_KEY"] = old_glm


if __name__ == "__main__":
    unittest.main()
