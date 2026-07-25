#!/usr/bin/env python3
"""
Run AOBTD against a set of local intentionally vulnerable benchmark targets.

The runner is intentionally boring:
  - start/health-check a target
  - optionally prime its demo database
  - run AOBTD with a consistent scan shape
  - emit bench/scorecard.py output

It avoids deleting anything. Existing containers/projects are reused when
possible; use Docker/Compose manually if you want to reset a lab completely.

Examples:
  python3 bench/run_targets.py --targets vampi,dvga --max-pages 60
  python3 bench/run_targets.py --targets dvwa --llm none --max-pages 30
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

import benchmark_matrix
import coverage_gate
import juice_coverage
import scorecard
import vulnerableapp_benchmark


ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = Path("/tmp/aobtd-bench-src")
RUN_ROOT = Path("/tmp/aobtd-bench-runs")
DEFAULT_BINARY = Path("/tmp/aobtd-bench")
REMOTE_OPENAI_COMPAT_DEFAULT = "https://api.z.ai/api/paas/v4"


@dataclass
class Target:
    name: str
    kind: str
    target_url: str
    health_url: str
    source_repo: str = ""
    source_dir: Path | None = None
    image: str = ""
    container_name: str = ""
    docker_args: list[str] = field(default_factory=list)
    compose_files: list[Path] = field(default_factory=list)
    compose_project: str = ""
    prime_urls: list[str] = field(default_factory=list)
    seed_urls: list[str] = field(default_factory=list)
    login_url: str = ""
    login_api_url: str = ""
    login_user: str = ""
    login_pass: str = ""
    session_cookie: str = ""
    analysis_endpoint_limit: int = 0
    notes: str = ""


TARGETS: dict[str, Target] = {
    "juice": Target(
        name="juice",
        kind="docker",
        image="bkimminich/juice-shop:latest",
        container_name="aobtd-bench-juice",
        docker_args=[
            "-p",
            "127.0.0.1:3001:3000",
        ],
        target_url="http://127.0.0.1:3001/",
        health_url="http://127.0.0.1:3001/",
        notes="OWASP Juice Shop SPA benchmark. Use bench/juice_coverage.py snapshots for exact challenge deltas.",
    ),
    "vampi": Target(
        name="vampi",
        kind="docker",
        image="erev0s/vampi:latest",
        container_name="aobtd-bench-vampi",
        docker_args=[
            "-e",
            "vulnerable=1",
            "-e",
            "tokentimetolive=3600",
            "-p",
            "127.0.0.1:5002:5000",
        ],
        target_url="http://127.0.0.1:5002/ui/",
        health_url="http://127.0.0.1:5002/",
        prime_urls=["http://127.0.0.1:5002/createdb"],
        seed_urls=["http://127.0.0.1:5002/openapi.json"],
        notes="Lightweight REST API with Swagger UI and OWASP API Top 10 style flaws.",
    ),
    "dvga": Target(
        name="dvga",
        kind="docker",
        image="dolevf/dvga:latest",
        container_name="aobtd-bench-dvga",
        docker_args=[
            "-e",
            "WEB_HOST=0.0.0.0",
            "-p",
            "127.0.0.1:5013:5013",
        ],
        target_url="http://127.0.0.1:5013/",
        health_url="http://127.0.0.1:5013/",
        notes="GraphQL-specific vulnerable app.",
    ),
    "dvwa": Target(
        name="dvwa",
        kind="compose",
        source_repo="https://github.com/digininja/DVWA.git",
        source_dir=SRC_ROOT / "dvwa",
        compose_files=[SRC_ROOT / "dvwa" / "compose.yml"],
        compose_project="aobtd-bench-dvwa",
        target_url="http://127.0.0.1:4280/",
        health_url="http://127.0.0.1:4280/login.php",
        prime_urls=["http://127.0.0.1:4280/setup.php"],
        login_url="http://127.0.0.1:4280/login.php",
        login_user="admin",
        login_pass="password",
        analysis_endpoint_limit=18,
        notes="Classic PHP/MariaDB vulnerable app. Needs setup.php DB init on first run.",
    ),
    "webgoat": Target(
        name="webgoat",
        kind="docker",
        image="webgoat/webgoat:latest",
        container_name="aobtd-bench-webgoat",
        docker_args=[
            "-p",
            "127.0.0.1:8085:8080",
            "-p",
            "127.0.0.1:9095:9090",
        ],
        target_url="http://127.0.0.1:8085/WebGoat/",
        health_url="http://127.0.0.1:8085/WebGoat/",
        login_url="http://127.0.0.1:8085/WebGoat/login",
        login_user="aobtd-bench",
        login_pass="Password1!",
        seed_urls=[
            "http://127.0.0.1:8085/WebGoat/SqlInjection.lesson.lesson",
            "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/SqlInjection.lesson",
            "http://127.0.0.1:8085/WebGoat/IDOR.lesson.lesson",
            "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/IDOR.lesson",
            "http://127.0.0.1:8085/WebGoat/MissingFunctionAC.lesson.lesson",
            "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/MissingFunctionAC.lesson",
            "http://127.0.0.1:8085/WebGoat/PathTraversal.lesson.lesson",
            "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/PathTraversal.lesson",
            "http://127.0.0.1:8085/WebGoat/XXE.lesson.lesson",
            "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/XXE.lesson",
            "http://127.0.0.1:8085/WebGoat/AuthBypass.lesson.lesson",
            "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/AuthBypass.lesson",
            "http://127.0.0.1:8085/WebGoat/JWT.lesson.lesson",
            "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/JWT.lesson",
            "http://127.0.0.1:8085/WebGoat/InsecureDeserialization.lesson.lesson",
            "http://127.0.0.1:8085/WebGoat/service/lessonoverview.mvc/InsecureDeserialization.lesson",
        ],
        notes="OWASP lesson app. Useful for navigation/auth workflow regressions.",
    ),
    "vulnerableapp": Target(
        name="vulnerableapp",
        kind="docker",
        image="sasanlabs/owasp-vulnerableapp:latest",
        container_name="aobtd-bench-vulnerableapp",
        docker_args=[
            "-p",
            "127.0.0.1:9091:9090",
        ],
        target_url="http://127.0.0.1:9091/VulnerableApp/",
        health_url="http://127.0.0.1:9091/VulnerableApp/",
        seed_urls=[
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
        notes="OWASP scanner-benchmark app with sitemap, scanner ground-truth JSON, and comparator endpoint.",
    ),
    "crapi": Target(
        name="crapi",
        kind="compose",
        source_repo="https://github.com/OWASP/crAPI.git",
        source_dir=SRC_ROOT / "crapi",
        compose_files=[
            SRC_ROOT / "crapi" / "deploy" / "docker" / "docker-compose.yml",
            SRC_ROOT / "crapi" / "deploy" / "docker" / "docker-compose.minimal.yml",
        ],
        compose_project="aobtd-bench-crapi",
        target_url="http://127.0.0.1:8888/",
        health_url="http://127.0.0.1:8888/",
        login_api_url="http://127.0.0.1:8888/identity/api/auth/login",
        login_user="aobtd-bench@example.com",
        login_pass="Password1!",
        seed_urls=[
            "http://127.0.0.1:8888/community/api/v2/community/posts/recent",
            "http://127.0.0.1:8888/identity/api/v2/user/dashboard",
            "http://127.0.0.1:8888/identity/api/v2/user/videos/convert_video",
            "http://127.0.0.1:8888/identity/api/v2/vehicle/vehicles",
            "http://127.0.0.1:8888/workshop/api/management/users/all",
            "http://127.0.0.1:8888/workshop/api/mechanic/",
            "http://127.0.0.1:8888/workshop/api/mechanic/mechanic_report",
            "http://127.0.0.1:8888/workshop/api/mechanic/receive_report",
            "http://127.0.0.1:8888/workshop/api/mechanic/service_requests",
            "http://127.0.0.1:8888/workshop/api/shop/orders/all",
            "http://127.0.0.1:8888/workshop/api/shop/orders/1",
            "http://127.0.0.1:8888/workshop/api/shop/orders/2",
            "http://127.0.0.1:8888/workshop/api/shop/orders/3",
            "http://127.0.0.1:8888/workshop/api/shop/products",
            "http://127.0.0.1:8888/workshop/api/shop/return_qr_code",
        ],
        notes="Modern microservice/API benchmark. Heavier startup, high value.",
    ),
}


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=True)


def capture(cmd: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.check_output(cmd, cwd=str(cwd) if cwd else None, text=True).strip()


def ensure_source(target: Target) -> None:
    if not target.source_repo or not target.source_dir:
        return
    SRC_ROOT.mkdir(parents=True, exist_ok=True)
    if (target.source_dir / ".git").exists():
        run(["git", "-C", str(target.source_dir), "pull", "--ff-only"])
    elif target.source_dir.exists():
        print(f"Source exists but is not a git checkout, leaving it alone: {target.source_dir}")
    else:
        run(["git", "clone", "--depth", "1", target.source_repo, str(target.source_dir)])


def container_exists(name: str) -> bool:
    if not name:
        return False
    out = capture(["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"])
    return any(line.strip() == name for line in out.splitlines())


def container_running(name: str) -> bool:
    if not name:
        return False
    out = capture(["docker", "ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}"])
    return any(line.strip() == name for line in out.splitlines())


def start_docker(target: Target) -> None:
    if container_running(target.container_name):
        print(f"{target.name}: container already running ({target.container_name})")
        return
    if container_exists(target.container_name):
        run(["docker", "start", target.container_name])
        return
    run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            target.container_name,
            *target.docker_args,
            target.image,
        ]
    )


def start_compose(target: Target) -> None:
    ensure_source(target)
    cmd = ["docker", "compose", "-p", target.compose_project]
    for compose_file in target.compose_files:
        cmd.extend(["-f", str(compose_file)])
    cmd.extend(["up", "-d"])
    env = os.environ.copy()
    if target.name == "crapi":
        # Keep crAPI on loopback and avoid enabling intentionally noisy shell/log4j paths by default.
        env.setdefault("LISTEN_IP", "127.0.0.1")
        env.setdefault("ENABLE_SHELL_INJECTION", "false")
        env.setdefault("ENABLE_LOG4J", "false")
    run(cmd, cwd=target.source_dir, env=env)


def start_target(target: Target) -> None:
    if target.kind == "docker":
        start_docker(target)
    elif target.kind == "compose":
        start_compose(target)
    else:
        raise SystemExit(f"Unknown target kind for {target.name}: {target.kind}")


def http_ok(url: str, timeout: float = 5.0) -> tuple[bool, int | None, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "AOBTD benchmark healthcheck"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status) < 500, int(resp.status), ""
    except urllib.error.HTTPError as exc:
        return int(exc.code) < 500, int(exc.code), str(exc)
    except Exception as exc:  # noqa: BLE001 - CLI health summary should show exact failure
        return False, None, str(exc)


def wait_health(target: Target, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        ok, status, err = http_ok(target.health_url)
        if ok:
            print(f"{target.name}: healthy at {target.health_url} (status {status})")
            return
        last = err or f"status {status}"
        time.sleep(3)
    raise SystemExit(f"{target.name}: health check failed after {seconds}s: {last}")


def prime_target(target: Target) -> None:
    if target.name == "dvwa":
        prime_dvwa(target)
        return
    if target.name == "webgoat":
        prime_webgoat(target)
        return
    if target.name == "crapi":
        prime_crapi(target)
        return
    for url in target.prime_urls:
        ok, status, err = http_ok(url)
        if ok:
            print(f"{target.name}: primed {url} (status {status})")
        else:
            print(f"{target.name}: prime warning for {url}: {err or status}")


def form_token(html: str) -> str:
    match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", html)
    return match.group(1) if match else ""


def cookie_header_from_jar(jar: http.cookiejar.CookieJar) -> str:
    pairs: list[str] = []
    wanted = {"PHPSESSID", "security"}
    for cookie in jar:
        if cookie.name in wanted:
            pairs.append(f"{cookie.name}={cookie.value}")
    return "; ".join(pairs)


def opener_request(
    opener: urllib.request.OpenerDirector,
    url: str,
    data: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> tuple[int, str, str]:
    encoded = None
    headers = {"User-Agent": "AOBTD benchmark target prep"}
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=encoded, headers=headers)
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
        return int(resp.status), resp.geturl(), body


def json_request(
    url: str,
    payload: dict[str, str],
    *,
    timeout: float = 20.0,
) -> tuple[int, dict[str, str], str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "AOBTD benchmark target prep",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), dict(exc.headers), exc.read().decode("utf-8", "replace")


def prime_dvwa(target: Target) -> None:
    base = target.target_url.rstrip("/")
    if base.endswith("/index.php"):
        base = base[: -len("/index.php")]
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    status, _, setup_html = opener_request(opener, f"{base}/setup.php")
    token = form_token(setup_html)
    if not token:
        raise SystemExit(f"{target.name}: setup token not found (status {status})")
    status, _, setup_result = opener_request(
        opener,
        f"{base}/setup.php",
        {"create_db": "Create / Reset Database", "user_token": token},
        timeout=60.0,
    )
    if "Setup successful" not in setup_result and "Database has been created" not in setup_result:
        print(f"{target.name}: setup warning, response did not include success marker (status {status})")

    status, _, login_html = opener_request(opener, f"{base}/login.php")
    token = form_token(login_html)
    if not token:
        raise SystemExit(f"{target.name}: login token not found (status {status})")
    status, final_url, login_result = opener_request(
        opener,
        f"{base}/login.php",
        {
            "username": target.login_user or "admin",
            "password": target.login_pass or "password",
            "Login": "Login",
            "user_token": token,
        },
    )
    if "logout.php" not in login_result and "index.php" not in final_url:
        print(f"{target.name}: login warning, authenticated marker not found (status {status}, url {final_url})")

    status, _, security_html = opener_request(opener, f"{base}/security.php")
    token = form_token(security_html)
    if not token:
        raise SystemExit(f"{target.name}: security token not found (status {status})")
    status, _, security_result = opener_request(
        opener,
        f"{base}/security.php",
        {"security": "low", "seclev_submit": "Submit", "user_token": token},
    )
    if "Security level set to low" not in security_result and "currently: <em>low</em>" not in security_result:
        print(f"{target.name}: security warning, low-security marker not found (status {status})")

    cookie = cookie_header_from_jar(jar)
    if not cookie or "PHPSESSID=" not in cookie or "security=low" not in cookie:
        raise SystemExit(f"{target.name}: failed to prepare session cookie, got {cookie!r}")
    target.session_cookie = cookie
    target.target_url = f"{base}/index.php"
    print(f"{target.name}: database reset, logged in as {target.login_user}, security=low, session cookie prepared")


def prime_webgoat(target: Target) -> None:
    base = target.target_url.rstrip("/")
    if base.endswith("/login"):
        base = base[: -len("/login")]
    username = target.login_user or "aobtd-bench"
    password = target.login_pass or "Password1!"

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    # Registering an existing user returns an application message but keeps
    # the flow usable, so registration is best-effort and login is the source
    # of truth.
    try:
        opener_request(opener, f"{base}/registration", timeout=30.0)
        status, final_url, register_result = opener_request(
            opener,
            f"{base}/register.mvc",
            {
                "username": username,
                "password": password,
                "matchingPassword": password,
                "agree": "agree",
            },
            timeout=30.0,
        )
        if status >= 400:
            print(f"{target.name}: registration warning, status {status} at {final_url}")
        elif any(marker in register_result.lower() for marker in ["already", "exists", "duplicate"]):
            print(f"{target.name}: benchmark user already exists, continuing to login")
    except Exception as exc:  # noqa: BLE001 - prep should continue to login for pre-created users
        print(f"{target.name}: registration warning: {exc}")

    status, final_url, login_result = opener_request(
        opener,
        f"{base}/login",
        {"username": username, "password": password},
        timeout=30.0,
    )
    login_text = login_result.lower()
    if "logout" not in login_text and "start.mvc" not in final_url and "welcome" not in login_text:
        print(f"{target.name}: login warning, authenticated marker not found (status {status}, url {final_url})")

    pairs = [f"{cookie.name}={cookie.value}" for cookie in jar if cookie.name == "JSESSIONID"]
    cookie = "; ".join(pairs)
    if not cookie:
        raise SystemExit(f"{target.name}: failed to prepare JSESSIONID cookie")
    target.session_cookie = cookie
    target.target_url = f"{base}/start.mvc"
    target.login_url = f"{base}/login"
    target.login_user = username
    target.login_pass = password
    print(f"{target.name}: registered/logged in as {username}, session cookie prepared")


def prime_crapi(target: Target) -> None:
    base = target.target_url.rstrip("/")
    email = target.login_user or "aobtd-bench@example.com"
    password = target.login_pass or "Password1!"
    phone = "5550001234"

    signup_status, _, signup_body = json_request(
        f"{base}/identity/api/auth/signup",
        {
            "name": "AOBTD Bench",
            "email": email,
            "number": phone,
            "password": password,
        },
        timeout=30.0,
    )
    signup_lower = signup_body.lower()
    if 200 <= signup_status < 300:
        print(f"{target.name}: benchmark user registered ({email})")
    elif any(marker in signup_lower for marker in ("already", "registered", "exists", "duplicate")):
        print(f"{target.name}: benchmark user already exists, continuing to login")
    else:
        print(
            f"{target.name}: signup warning for benchmark user "
            f"(status {signup_status}, body {signup_body[:160]!r}); continuing to login"
        )

    login_url = f"{base}/identity/api/auth/login"
    login_status, _, login_body = json_request(
        login_url,
        {"email": email, "password": password},
        timeout=30.0,
    )
    if login_status < 200 or login_status >= 300:
        raise SystemExit(
            f"{target.name}: benchmark user login failed "
            f"(status {login_status}, body {login_body[:200]!r})"
        )
    try:
        login_json = json.loads(login_body)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{target.name}: login returned invalid JSON: {exc}") from exc
    token = str(login_json.get("token") or "").strip()
    if not token:
        raise SystemExit(f"{target.name}: login succeeded but returned no token")

    target.login_api_url = login_url
    target.login_user = email
    target.login_pass = password
    print(f"{target.name}: registered/logged in as {email}, API token login prepared")


def build_binary(binary: Path) -> None:
    run(["go", "build", "-o", str(binary), "./cmd/aobtd"], cwd=ROOT)


def scan_command(
    binary: Path,
    target: Target,
    output_dir: Path,
    args: argparse.Namespace,
) -> list[str]:
    cmd = [
        str(binary),
        "scan",
        "--target",
        target.target_url,
        "--output",
        str(output_dir),
        "--port",
        str(args.proxy_port),
        "--headless=true",
        "--max-pages",
        str(args.max_pages),
        "--max-depth",
        str(args.max_depth),
        "--testing-authority",
        args.testing_authority,
        "--budget",
        str(args.budget),
        "--llm-input-budget",
        str(args.llm_input_budget),
        "--llm-output-budget",
        str(args.llm_output_budget),
        "--strategist-period",
        str(args.strategist_period),
    ]
    analysis_endpoint_limit = target.analysis_endpoint_limit or args.analysis_endpoint_limit
    if analysis_endpoint_limit:
        cmd.extend(["--analysis-endpoint-limit", str(analysis_endpoint_limit)])
    if args.llm != "none":
        cmd.extend(["--llm", args.llm, "--model", args.model])
        if args.llm_url:
            cmd.extend(["--llm-url", args.llm_url])
        if args.reasoning_model:
            cmd.extend(["--reasoning-model", args.reasoning_model])
    else:
        cmd.extend(["--llm", ""])
    if target.login_url and not target.session_cookie:
        cmd.extend(
            [
                "--login-url",
                target.login_url,
                "--login-user",
                target.login_user,
                "--login-pass",
                target.login_pass,
            ]
        )
    if target.login_api_url:
        cmd.extend(
            [
                "--login-api-url",
                target.login_api_url,
                "--login-user",
                target.login_user,
                "--login-pass",
                target.login_pass,
            ]
        )
    if target.session_cookie:
        cmd.extend(["--session-cookie", target.session_cookie])
    for seed_url in target.seed_urls:
        cmd.extend(["--seed-url", seed_url])
    return cmd


def provider_failure_reason(line: str) -> str:
    lower = line.lower()
    if "insufficient balance" in lower or "no resource package" in lower:
        return "provider_resource_exhausted"
    if "resource_exhausted" in lower:
        return "provider_rate_limited"
    if "api error 429" in lower or "http_429" in lower or "status 429" in lower:
        return "provider_rate_limited"
    if "no rate limit" in lower or "no rate limiting" in lower:
        return ""
    rate_limit_text = "rate limit" in lower or "rate_limited" in lower or "rate limited" in lower
    provider_context = any(
        marker in lower
        for marker in (
            "llm",
            "provider",
            "openai",
            "anthropic",
            "minimax",
            "z.ai",
            "bigmodel",
            "chat/completions",
            "api request",
            "api error",
            "completion",
        )
    )
    if rate_limit_text and provider_context:
        return "provider_rate_limited"
    if "quota" in lower and ("exceeded" in lower or "exhausted" in lower):
        return "provider_quota_exhausted"
    return ""


def openai_compatible_key_names(base_url: str = "", model: str = "") -> tuple[str, ...]:
    lower_url = (base_url or "").lower()
    lower_model = (model or "").lower()
    if "minimax" in lower_url or lower_model.startswith("minimax"):
        return ("MINIMAX_API_KEY", "ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY")
    if "z.ai" in lower_url or "bigmodel" in lower_url or lower_model.startswith("glm-"):
        return ("ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY", "MINIMAX_API_KEY")
    return ("ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY", "MINIMAX_API_KEY")


def resolve_llm_api_key(provider: str, base_url: str = "", model: str = "") -> str:
    if os.environ.get("AOBTD_LLM_KEY"):
        return os.environ["AOBTD_LLM_KEY"]
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY", "")
    if provider == "anthropic":
        return os.environ.get("ANTHROPIC_API_KEY", "")
    if provider == "openai-compatible":
        for name in openai_compatible_key_names(base_url, model):
            if os.environ.get(name):
                return os.environ[name]
    return ""


def load_dotenv_local(path: Path = ROOT / ".env.local") -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or os.environ.get(key):
            continue
        value = value.strip()
        if len(value) >= 2 and ((value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")):
            value = value[1:-1]
        os.environ[key] = value


def default_llm_base_url(provider: str) -> str:
    if provider == "ollama":
        return "http://localhost:11434/v1"
    if provider == "openai":
        return "https://api.openai.com/v1"
    if provider == "openai-compatible":
        return REMOTE_OPENAI_COMPAT_DEFAULT
    return ""


def llm_preflight_payload(model: str) -> dict:
    payload: dict[str, object] = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with OK."}],
        "max_tokens": 2,
        "temperature": 0,
    }
    if model.lower().startswith("glm-"):
        payload["thinking"] = {"type": "disabled"}
        payload["reasoning_effort"] = "none"
    return payload


def safe_preflight_error_summary(exc: Exception | urllib.error.HTTPError) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read().decode("utf-8", "replace")
        finally:
            exc.close()
        reason = provider_failure_reason(body)
        if reason:
            return reason
        compact = " ".join(body.split())
        return f"http_{exc.code}: {compact[:180]}"
    return " ".join(str(exc).split())[:180]


def preflight_llm(args: argparse.Namespace) -> tuple[bool, str]:
    provider = args.llm
    if provider in ("", "none"):
        return True, "skipped:llm_disabled"
    if provider == "anthropic":
        # The benchmark runner currently drives OpenAI-compatible APIs. Do not
        # invent a partial Anthropic probe here; the Go provider remains the
        # source of truth for Anthropic scans.
        return True, "skipped:unsupported_provider"

    base_url = (args.llm_url or default_llm_base_url(provider)).rstrip("/")
    if not base_url:
        return False, "missing_base_url"

    api_key = resolve_llm_api_key(provider, base_url, args.model)
    if provider in ("openai", "openai-compatible") and api_key == "" and "localhost" not in base_url and "127.0.0.1" not in base_url:
        return False, "missing_api_key"

    req = urllib.request.Request(
        base_url + "/chat/completions",
        data=json.dumps(llm_preflight_payload(args.model)).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "AOBTD benchmark preflight"},
    )
    if api_key:
        req.add_header("Authorization", "Bearer " + api_key)
    try:
        with urllib.request.urlopen(req, timeout=args.preflight_timeout) as resp:
            if int(resp.status) == 200:
                return True, "ok"
            return False, f"http_{int(resp.status)}"
    except urllib.error.HTTPError as exc:
        return False, safe_preflight_error_summary(exc)
    except Exception as exc:  # noqa: BLE001 - CLI preflight should summarize exact failure
        return False, safe_preflight_error_summary(exc)


def summarize_log_health(log_path: Path) -> dict[str, int | str | list[str]]:
    health: dict[str, int | str | list[str]] = {
        "warnings": 0,
        "provider_failures": 0,
        "provider_resource_exhausted": 0,
        "provider_rate_limited": 0,
        "provider_quota_exhausted": 0,
        "samples": [],
    }
    if not log_path.exists():
        return health
    samples: list[str] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            lower = line.lower()
            if "level=warn" in lower or " warning" in lower:
                health["warnings"] = int(health["warnings"]) + 1
            reason = provider_failure_reason(line)
            if reason:
                health["provider_failures"] = int(health["provider_failures"]) + 1
                health[reason] = int(health[reason]) + 1
                if len(samples) < 5:
                    samples.append(line.strip()[:300])
    health["samples"] = samples
    return health


def run_scan(binary: Path, target: Target, args: argparse.Namespace) -> dict:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = RUN_ROOT / f"{stamp}-{target.name}"
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = scan_command(binary, target, output_dir, args)
    log_path = output_dir / "scan.log"
    print(f"{target.name}: scan output -> {output_dir}", flush=True)
    started = time.time()
    terminated_for_provider = ""
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=os.environ.copy(),
        )
        assert proc.stdout is not None
        last_emit = 0.0
        for line in proc.stdout:
            log.write(line)
            log.flush()
            reason = provider_failure_reason(line)
            if reason and not args.keep_going_on_provider_error:
                terminated_for_provider = reason
                print(
                    f"{target.name}: stopping scan early due to {reason}; see {log_path}",
                    flush=True,
                )
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                break
            now = time.time()
            if now - last_emit > 15:
                print(f"{target.name}: {line.rstrip()[:220]}", flush=True)
                last_emit = now
        code = proc.wait()
        if terminated_for_provider:
            code = 86
    elapsed = time.time() - started
    db_path = output_dir / "scan.db"
    log_health = summarize_log_health(log_path)
    result = {
        "target": target.name,
        "url": target.target_url,
        "output_dir": str(output_dir),
        "db": str(db_path),
        "log": str(log_path),
        "exit_code": code,
        "elapsed_seconds": round(elapsed, 2),
        "log_health": log_health,
        "scan_config": {
            "llm": args.llm,
            "llm_url": args.llm_url if args.llm != "none" else "",
            "model": args.model if args.llm != "none" else "",
            "reasoning_model": args.reasoning_model,
            "max_pages": args.max_pages,
            "max_depth": args.max_depth,
            "testing_authority": args.testing_authority,
            "budget": args.budget,
            "strategist_period": args.strategist_period,
            "seed_count": len(target.seed_urls),
        },
    }
    if terminated_for_provider:
        result["terminated_reason"] = terminated_for_provider

    # Write operational metadata before scoring so scorecard.summarize_scan can
    # include exit codes, provider failures, and termination reasons in the
    # benchmark-quality gate. The final write below embeds the scorecard too.
    metadata_path = output_dir / "run_metadata.json"
    metadata_path.write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )

    if db_path.exists():
        result["scorecard"] = scorecard.summarize_scan(db_path)
        result["coverage"] = coverage_gate.evaluate_coverage(db_path, target=target.name)
        (output_dir / "scorecard.md").write_text(
            scorecard.render_markdown(result["scorecard"]), encoding="utf-8"
        )
        (output_dir / "scorecard.json").write_text(
            json.dumps(result["scorecard"], indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (output_dir / "coverage.md").write_text(
            coverage_gate.render_markdown(result["coverage"]), encoding="utf-8"
        )
        (output_dir / "coverage.json").write_text(
            json.dumps(result["coverage"], indent=2, sort_keys=True),
            encoding="utf-8",
        )
        if target.name == "vulnerableapp":
            result["vulnerableapp_benchmark"] = vulnerableapp_benchmark.evaluate_scan(
                db_path,
                target.target_url,
            )
            (output_dir / "vulnerableapp_benchmark.md").write_text(
                vulnerableapp_benchmark.render_markdown(result["vulnerableapp_benchmark"]),
                encoding="utf-8",
            )
            (output_dir / "vulnerableapp_benchmark.json").write_text(
                json.dumps(result["vulnerableapp_benchmark"], indent=2, sort_keys=True),
                encoding="utf-8",
            )
        if target.name == "juice":
            snapshot = juice_coverage.fetch_challenges(target.target_url)
            result["juice_coverage"] = juice_coverage.summarize_snapshot(snapshot)
            (output_dir / "juice_coverage_snapshot.json").write_text(
                json.dumps(snapshot, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            (output_dir / "juice_coverage.md").write_text(
                juice_coverage.render_summary(result["juice_coverage"]),
                encoding="utf-8",
            )
            (output_dir / "juice_coverage.json").write_text(
                json.dumps(result["juice_coverage"], indent=2, sort_keys=True),
                encoding="utf-8",
            )
        print(scorecard.render_markdown(result["scorecard"]).split("### Confirmed findings")[0])
        print(coverage_gate.render_markdown(result["coverage"]).split("| Check |")[0])
    else:
        print(f"{target.name}: no scan.db produced")
    metadata_path.write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )
    return result


def parse_targets(raw: str) -> list[Target]:
    names = [p.strip() for p in raw.split(",") if p.strip()]
    unknown = [name for name in names if name not in TARGETS]
    if unknown:
        raise SystemExit(f"Unknown target(s): {', '.join(unknown)}. Available: {', '.join(TARGETS)}")
    return [TARGETS[name] for name in names]


def render_plan(targets: Iterable[Target]) -> None:
    print("Benchmark targets:")
    for target in targets:
        seed_note = f" ({len(target.seed_urls)} seeds)" if target.seed_urls else ""
        print(f"- {target.name}: {target.target_url}{seed_note} — {target.notes}")


def select_matrix_rows(rows: list[benchmark_matrix.MatrixRow], mode: str) -> list[benchmark_matrix.MatrixRow]:
    if mode == "raw":
        return benchmark_matrix.latest_per_target(rows)
    if mode == "comparable":
        return benchmark_matrix.latest_per_target(rows, comparable_only=True)
    if mode == "ready":
        return benchmark_matrix.latest_per_target(rows, benchmark_ready_only=True)
    raise ValueError(f"unknown matrix mode: {mode}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--targets",
        default="juice,vampi,dvga,dvwa,webgoat,vulnerableapp,crapi",
        help=f"Comma-separated target names. Available: {', '.join(TARGETS)}",
    )
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--start-only", action="store_true")
    parser.add_argument("--score-only", type=Path, default=None, help="Only score this scan.db")
    parser.add_argument("--health-timeout", type=int, default=180)
    parser.add_argument("--max-pages", type=int, default=70)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--proxy-port", type=int, default=8089)
    parser.add_argument("--testing-authority", default="full_control")
    parser.add_argument("--llm", default="openai-compatible")
    parser.add_argument("--llm-url", default="https://api.z.ai/api/paas/v4")
    parser.add_argument("--model", default="glm-5.2")
    parser.add_argument("--reasoning-model", default="")
    parser.add_argument("--budget", type=int, default=0)
    parser.add_argument(
        "--analysis-endpoint-limit",
        type=int,
        default=0,
        help="Override per-pass Analyzer endpoint-family cap (0 = target/default scanner behavior).",
    )
    parser.add_argument(
        "--llm-input-budget",
        type=int,
        default=80_000,
        help="Max LLM input tokens per scanner run. Benchmark default is intentionally tight; pass 0 for unlimited.",
    )
    parser.add_argument(
        "--llm-output-budget",
        type=int,
        default=30_000,
        help="Max LLM output tokens per scanner run. Benchmark default is intentionally tight; pass 0 for unlimited.",
    )
    parser.add_argument("--strategist-period", type=int, default=0)
    parser.add_argument(
        "--keep-going-on-provider-error",
        action="store_true",
        help="Do not stop early when the scan log shows provider quota/resource exhaustion.",
    )
    parser.add_argument(
        "--no-matrix",
        action="store_true",
        help="Do not render the suite-level benchmark matrix after running scans.",
    )
    parser.add_argument(
        "--matrix-mode",
        choices=["ready", "comparable", "raw"],
        default="ready",
        help="Suite matrix mode to print after scans. 'ready' requires comparable scan quality plus passing coverage.",
    )
    parser.add_argument(
        "--no-preflight-llm",
        action="store_true",
        help="Skip the one-call LLM provider preflight before starting benchmark scans.",
    )
    parser.add_argument(
        "--preflight-timeout",
        type=float,
        default=20.0,
        help="Seconds to wait for the LLM provider preflight request.",
    )
    args = parser.parse_args()

    if args.score_only:
        print(scorecard.render_markdown(scorecard.summarize_scan(args.score_only)))
        return 0

    load_dotenv_local()
    selected = parse_targets(args.targets)
    render_plan(selected)
    if not args.skip_build:
        build_binary(args.binary)
    if not args.start_only and not args.no_preflight_llm and args.llm != "none":
        ok, detail = preflight_llm(args)
        if not ok:
            raise SystemExit(
                f"LLM preflight failed before starting target scans: {detail}. "
                "Fix the provider/key/quota or pass --no-preflight-llm to run anyway."
            )
        print(f"LLM preflight: {detail}")

    results = []
    for target in selected:
        print(f"\n=== {target.name} ===", flush=True)
        start_target(target)
        wait_health(target, args.health_timeout)
        prime_target(target)
        if args.start_only:
            continue
        result = run_scan(args.binary, target, args)
        results.append(result)

    if results:
        RUN_ROOT.mkdir(parents=True, exist_ok=True)
        summary_path = RUN_ROOT / f"summary-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        summary_path.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nBenchmark summary written: {summary_path}")
        if not args.no_matrix:
            print()
            rows = select_matrix_rows(benchmark_matrix.collect_rows(RUN_ROOT), args.matrix_mode)
            print(benchmark_matrix.render_markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
