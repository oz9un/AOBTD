# AOBTD Demo Labs Runbook

Last validated: 2026-08-01, local authorized lab targets only.

## Recommendation

Lead with DVWA in walkthrough mode. It is compact, familiar, and the current run has five confirmed findings, including a critical OS command injection plus replayable SQL injection and schema-exposure proof.

Use VAmPI as a short "API target" backup clip. It produced clear findings, but the scan ended `incomplete` after hitting the LLM input budget.

Use VulnerableApp only as an offline confidence slide or appendix. It is impressive but noisy for a main demo: 86 confirmed findings can look like a benchmark dump rather than an assistant story.

Avoid Juice Shop as the main demo target. It creates the wrong audience expectation: people may judge the demo against the full Juice Shop challenge catalog instead of judging whether AOBTD can map, reason, and prove a bounded finding.

## Known-Good Runs

DVWA:

- Output: `/tmp/aobtd-bench-runs/20260801-235422-dvwa`
- Status: `completed`
- Duration: 5.8m
- Coverage gate: `pass`, 4/4
- Findings: 17 total, 5 confirmed, 5 retest-ready
- Confirmed proof: OS command injection with `ip=127.0.0.1; whoami`
- Confirmed proof: IDOR across `/vulnerabilities/api/v2/user/1` and `/vulnerabilities/api/v2/user/2`
- Confirmed proof: SQL injection on the brute-force login username parameter
- Confirmed proof: SQL syntax error with `id=%27`
- Confirmed proof: UNION schema exposure with the UNION payload in the actual replay request

VAmPI:

- Output: `/tmp/aobtd-bench-runs/20260801-224155-vampi`
- Status: `incomplete`
- Coverage gate: `pass`, 3/3
- Findings: 18 total, 4 confirmed
- Confirmed proof: exposed Werkzeug console at `/console`
- Confirmed proof: plaintext passwords at `/users/v1/_debug`
- Confirmed proof: empty registration fields accepted at `/users/v1/register`

VulnerableApp:

- Output: `/tmp/aobtd-bench-runs/20260801-224457-vulnerableapp`
- Status: `completed`
- Coverage gate: `pass`, 12/12
- Findings: 95 total, 86 confirmed, 86 retest-ready
- Confirmed proof examples: command injection echo nonce, LDAP wildcard expansion, SQLi, and path traversal lesson files

## Recording Path

1. Start from a completed DVWA run:

   ```bash
   ./aobtd ui --input /tmp/aobtd-bench-runs/20260801-235422-dvwa --port 18080 --no-browser
   ```

2. Open:

   ```text
   http://127.0.0.1:18080/#/scan/1/overview
   ```

3. Show the overview for 10-15 seconds:

   - target: `127.0.0.1:4280`
   - status: completed
   - runtime: about 5.8m
   - profiled pages: 28
   - traffic: 214 requests
   - confirmed findings: 5
   - one critical finding

4. Click `Findings`.

5. Show that confirmed findings are separated from possible hypotheses.

6. Click `Start walkthrough`.

7. Narrate the first finding:

   - AOBTD replays the observed command-injection form as POST data.
   - The payload is `127.0.0.1; whoami`.
   - The response contains command-output evidence for the web-server user.
   - This is the strongest "receipt" in the recording: request, parameter, payload, response.

8. Click `Next` until the SQLi finding.

9. Narrate the SQLi finding:

   - AOBTD observed an input-looking `id` parameter.
   - It ran a bounded baseline-diff SQLi probe.
   - The replay request is `GET /vulnerabilities/sqli/?Submit=Submit&id=%27`.
   - The response includes a MariaDB SQL syntax error.

10. Click `Next`.

11. Narrate the schema-exposure finding:

   - After confirming SQLi, AOBTD searched for a UNION shape.
   - It used the confirmed shape to query `information_schema.columns`.
   - The replay request contains the UNION payload in the actual URL, not only in a note.

## Exact Benchmark Commands

DVWA:

```bash
python3 bench/run_targets.py --targets dvwa --proxy-port 18098 --max-pages 40 --max-depth 7 --llm openai --llm-url https://api.openai.com/v1 --model gpt-4.1-mini --reasoning-model gpt-5-mini --llm-input-budget 150000 --llm-output-budget 35000 --no-matrix
```

VAmPI:

```bash
python3 bench/run_targets.py --targets vampi --proxy-port 18092 --max-pages 50 --max-depth 7 --llm openai --llm-url https://api.openai.com/v1 --model gpt-4.1-mini --reasoning-model gpt-5-mini --llm-input-budget 60000 --llm-output-budget 20000 --no-matrix
```

VulnerableApp:

```bash
python3 bench/run_targets.py --targets vulnerableapp --proxy-port 18093 --max-pages 50 --max-depth 7 --llm openai --llm-url https://api.openai.com/v1 --model gpt-4.1-mini --reasoning-model gpt-5-mini --llm-input-budget 80000 --llm-output-budget 24000 --no-matrix
```

## Preflight

Use an alternate proxy port. Port `8089` was already occupied by an existing scan in this workspace during validation.

```bash
go test ./... -count=1
go build -o aobtd ./cmd/aobtd
```

Do not run scans against public third-party targets unless they are explicitly in scope and authorized.

## Caveats To Say Out Loud

AOBTD is not claiming exhaustive benchmark completion. The demo claim is narrower and stronger: it can map an app, select likely attack surfaces, actively verify findings on authorized targets, and produce retestable proof.

For prerecorded delivery, show the completed run and walkthrough. Do not make the audience wait through model budget warnings unless you want to discuss operational constraints.
