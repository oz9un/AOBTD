# AOBTD Demo Storyboard

## Core Story

This is not a "look, another scanner found DVWA bugs" demo.

The story is: AOBTD behaves like a cautious security assistant. It maps the app, forms hypotheses, actively tests only what it is allowed to test, separates guesses from confirmed proof, and turns observed leads into retestable impact: IDOR, SQLi, schema exposure, and command execution.

The audience should leave with this sentence in their head:

> It does not just list possible bugs. It earns confirmed findings with receipts.

## Title

Assistant with Receipts: From App Map to Proof of Exploit

Backup title:

The Difference Between "Maybe Vulnerable" and "Here Is the Request"

## 6-Minute Arc

### 0:00-0:40 - The Problem

Say:

> DAST tools usually give you two bad feelings: either a wall of possible findings, or a benchmark scoreboard that hides the actual reasoning. What I wanted to show is different: can an assistant explore an app, explain what it thinks matters, and only promote a finding when it has replayable proof?

Show:

- AOBTD overview landing page.
- The numbers: 28 profiles, 214 requests, 5 confirmed findings, 1 critical.

Point:

> The important number is not "17 findings." The important number is "5 confirmed." Everything else stays visibly separated as possible or hypothesis-level evidence.

### 0:40-1:30 - The Map

Say:

> First it builds a model of the target: routes, forms, inputs, stack, and traffic. This part is boring in the best possible way. If the map is bad, the exploit story is fake.

Show:

- Overview page.
- Surface cards: endpoints, inputs, profiles, traffic.
- Stack: Apache/PHP.

Point:

> This is why I am not starting with Juice Shop. I do not want the demo judged against a giant challenge catalog. I want to show the workflow: observe, choose, verify, explain.

### 1:30-2:30 - The First Receipt

Show:

- Findings page.
- Click `Start walkthrough`.
- Critical command-injection finding.

Say:

> The assistant finds a command-execution form, but it does not stop at "this looks like DVWA." It replays the form as POST data, injects a bounded `whoami` payload, and only promotes the finding when the response contains command-output evidence.

Show in walkthrough:

- Target URL `/vulnerabilities/exec/`.
- Parameter: `ip`.
- Payload: `127.0.0.1; whoami`.
- Verification note.
- Summary/steps.

Point:

> This is the first receipt: not a suspicion of RCE, but a replayable request with response evidence.

### 2:30-3:30 - From Bug to Impact

Click through to the SQL injection findings.

Say:

> The second arc is SQL injection. AOBTD first earns the basic proof with a SQL error, then asks whether the bug has impact beyond an error page. It searches for a UNION shape and reads schema metadata from `information_schema.columns`.

Show:

- SQLi syntax-error finding.
- SQLi schema exposure finding.
- Replay URL containing the UNION payload.

Point:

> This is the second receipt: the payload is in the actual request line. It is not a screenshot annotation. It is a retestable request.

### 3:30-4:20 - Why This Is Trustworthy

Say:

> A useful assistant also has to be willing to say "not proven." In this same run, possible hypotheses around file inclusion, upload, CAPTCHA, and headers stay below the line unless a deterministic probe or reasoner-backed retest reproduces them.

Show:

- Findings table with confirmed rows at the top and `POSSIBLE` rows below.

Point:

> This is the trust boundary of the demo. It is allowed to be curious. It is not allowed to pretend.

### 4:20-5:20 - "Not Just DVWA" Montage

Say:

> I also ran it on a couple of local lab targets with different shapes, because DVWA alone is too classic.

Show either screenshots or quick UI/database excerpts:

- VAmPI: Werkzeug console exposed at `/console`.
- VAmPI: `_debug` endpoint exposing users and passwords.
- VulnerableApp: command injection with an echoed nonce.

Point:

> Different target shapes, same standard: confirmed finding means there is a request and evidence.

### 5:20-6:00 - Close

Say:

> The claim is not "AOBTD finds every vulnerability." That would be the wrong claim and honestly a boring one. The claim is: an assistant can move from application understanding to attack selection to active verification, and can show exactly why a finding crossed the line from possible to confirmed.

End on:

> Map the application. Build the attack. Prove the hit.

## Best Single Sentence

If you only remember one line:

> AOBTD is not a vulnerability slot machine; it is an assistant that has to show its work before it gets to call something confirmed.

## What To Avoid Saying

- Do not say it finds all DVWA, Juice Shop, or benchmark vulnerabilities.
- Do not frame the demo as a benchmark race.
- Do not apologize for only two confirmed DVWA findings. Two clean receipts are stronger than a noisy pile.
- Do not linger on LLM budgets unless asked.

## If Someone Challenges The DVWA Choice

Say:

> DVWA is the microscope, not the benchmark. I am using it because the audience can recognize the vulnerability class quickly, so the demo can focus on the assistant workflow and proof quality. I also ran API-style and benchmark-style local labs to make sure this was not just a one-target trick.

Then mention:

- VAmPI found exposed debug/API data.
- This DVWA run now has a critical command-injection proof, plus VAmPI and VulnerableApp gave separate API and benchmark-app confidence.

## If Someone Asks "Why Not Juice Shop?"

Say:

> Juice Shop is great, but it changes the social contract of the demo. The audience starts counting challenge coverage. That is useful for benchmarking, but this demo is about assistant behavior: how it narrows, verifies, and explains.

## Visual Rhythm

Use three visual beats:

1. Overview: "Here is the map."
2. Command injection: "Here is execution proof."
3. SQL injection: "Here is impact escalation."

Then one fast montage:

- VAmPI debug console.
- VAmPI password exposure.
- VulnerableApp command injection nonce.

## Demo Promise

The clean promise:

> On authorized targets, AOBTD can explore like an assistant, verify like a tester, and report like someone who knows the difference between a lead and proof.
