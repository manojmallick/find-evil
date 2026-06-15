# 📋 Devpost Submission Form — paste-ready fields

Copy each block into the matching field on Devpost. Order follows the form.

---

## SCREEN: Project overview → General info

### Project name  (60 char max)
```
Find Evil! — Verifiable Autonomous IR Agent
```

### Elevator pitch / tagline  (200 char max)
```
An autonomous incident-response agent for SANS SIFT that physically can't tamper with evidence or hallucinate findings — every result traces to a logged tool call you can verify in under 10 seconds.
```

### Thumbnail
Upload **`assets/cover.png`** (Edit thumbnail → upload). It's 1280×800, reads
well at Devpost's 3:2.

---

## SCREEN: About the project  (Markdown — keep the pre-filled ## headers)

```markdown
## Inspiration

AI-powered attackers move in minutes. The obvious fix — point an AI agent at a forensic workstation — breaks two ways that make it unusable for real casework: the agent can **destroy the evidence** it's analyzing (an agent with a shell can `rm`, `dd`, or overwrite a disk image), and it **hallucinates findings** you can't verify ("PsExec ran at 14:22" — no artifact, no proof). In a real incident, an unverifiable finding is worse than no finding: it wastes the one thing you don't have at 3 AM — analyst time. We built Find Evil! to prove both problems are solvable **architecturally**, not with a longer prompt.

## What it does

Find Evil! is an autonomous incident-response agent for the SANS SIFT Workstation. Point it at a mounted disk image (and optionally a memory dump) and it runs a six-phase analysis the way a senior analyst does — triage, timeline, memory, artifacts, correlation, report — sequencing tools, recognizing anomalies, and self-correcting.

It runs in **two modes**: a deterministic, reproducible pipeline (court-defensible — the same case always runs the same way), and an **autonomous mode** where a Claude model drives the investigation: choosing the next tool from what it has found, narrating its reasoning, forming and testing hypotheses. The crucial property: **the architectural guarantees hold in both modes.**

Two things are made architecturally impossible:
- **Evidence tampering** — the agent has no shell. `rm`, `dd`, `curl`, `ssh` do not exist in its tool surface; destructive/exfil commands are blocked in code before any process spawns.
- **Hallucinated findings** — every CONFIRMED finding must carry a tool `call_id` present in the audit log, or the report refuses to generate it. **0% hallucination in the CONFIRMED tier, by construction.**

Any finding can be verified in under 10 seconds: grep its `call_id` against the audit log and get the exact tool, the exact arguments, and the SHA256 of the output that produced it. Full chain of custody.

## How we built it

- **Language:** Python 3.11
- **Tool layer:** a custom MCP server (FastMCP) exposing **10 typed forensic tools** wrapping SANS SIFT tooling — log2timeline/plaso, Volatility 3 (pslist/malfind/netscan), RegRipper, YARA, plus timestomping detection ($STANDARD_INFORMATION vs $FILE_NAME).
- **Guardrails:** a single `_safe_run()` chokepoint runs every command with `shell=False`; Pydantic validates every path; a `BLOCKED_COMMANDS`/`PROTECTED_WRITE_PATHS` list rejects destructive/exfil actions and writes to evidence paths — all before a subprocess spawns.
- **Agent:** a deterministic 6-phase orchestrator with bounded self-correction, plus an autonomous Claude-driven mode (manual tool-use loop) that keeps the same audited tool surface.
- **Integrity:** an append-only JSONL audit log; every tool call (executed or blocked) gets a UUID and a SHA256 of its output. The report generator rejects any untraceable CONFIRMED finding.
- **Quality bar:** 56 automated tests + a reproducible accuracy benchmark that runs with no evidence required.

## Challenges we ran into

- **Injection through tool arguments**, not just the command line — e.g. `parsers="mft; rm /cases/x"`. Solved with argument-level screening *plus* `shell=False`, so even an unscreened payload is an inert string.
- **Keeping integrity under an autonomous LLM.** When a model drives tool selection, what stops it confirming a finding it can't prove? Our answer: the report generator verifies every CONFIRMED `call_id` against the audit log — we have a test proving an LLM-invented `call_id` is rejected. Full autonomy, zero loss of integrity.
- **Defining "hallucination" rigorously** enough to enforce in code: traceability to a logged `call_id`, checked at report-generation time, not at prompt time.
- **Resisting the temptation to fake demo numbers.** We built a synthetic, fully-known dataset instead, so the metrics are real and reproducible.

## Accomplishments that we're proud of

- 12 documented bypass attempts (injection, command-chaining, exfiltration, prompt injection) — **all blocked, each turned into a passing regression test.**
- A 0%-hallucination guarantee that's **mechanically enforced**, not promised — and that holds even when an autonomous LLM is in control.
- A report where any finding is verifiable in under 10 seconds via its `call_id`.
- 56 passing tests, 10 typed forensic tools, and a one-command install.

## What we learned

- **Architectural constraints beat prompt-based ones.** "The agent can't run `rm`" is only true if the capability doesn't exist — telling a model not to is not a control.
- **Autonomy and safety aren't a trade-off** if the safety is structural: we gave a reasoning LLM full control of the investigation and it still can't tamper or fabricate.
- **For forensics, traceability is the product.** A finding you can't grep back to a tool call is, for an analyst, indistinguishable from a guess.

## What's next for Find Evil!

- macOS/Linux artifact phases (currently Windows-focused).
- Encrypted-volume handling when keys are available.
- A web UI over the existing JSON report + audit log.
```

> After pasting, change the last header from "What's next for Untitled" to
> **"What's next for Find Evil!"** (Devpost auto-fills your project name there).

---

## FIELD: Built with  (comma-separated tags)
```
python, anthropic-claude, mcp, fastmcp, pydantic, volatility3, log2timeline, plaso, regripper, yara, sans-sift, pytest, dfir
```

---

## FIELD: URL to your open source code repository
```
https://github.com/manojmallick/find-evil
```

---

## FIELD: Live deployment URL OR step-by-step instructions to run locally

```
No hosted URL — this is a local forensic tool. Two ways to run it:

A) Verify everything in 30 seconds on any laptop (no SIFT, no evidence):
   git clone https://github.com/manojmallick/find-evil.git
   cd find-evil
   python3 -m venv .venv && source .venv/bin/activate
   pip install -e ".[dev]"
   python3 -m pytest tests/                                  # 56 passed (incl. 12/12 bypass blocks)
   python3 tests/benchmark/run_benchmark.py --dataset synthetic   # precision/recall + 0% hallucination
   bash demo.sh                                              # full guided demo (pre-built sample case)

   Sample outputs (audit log + report) are in docs/sample_run/.
   Verify any finding:  grep <call_id> docs/sample_run/tool_calls.jsonl | python3 -m json.tool

B) Run against real evidence on a SANS SIFT Workstation:
   curl -fsSL https://raw.githubusercontent.com/manojmallick/find-evil/main/install.sh | bash
   sudo ewfmount evidence.E01 /mnt/ewf/ && sudo mount -o ro,loop,noatime /mnt/ewf/ewf1 /mnt/case_disk
   mkdir -p /cases/CASE001
   find-evil --case /cases/CASE001 --disk /mnt/case_disk --memory /cases/CASE001/memory.raw
   # Autonomous mode (needs ANTHROPIC_API_KEY): add --reasoning

Full instructions: README.md and case-templates/CLAUDE.md in the repo.
```

---

## FIELD: Evidence Dataset Documentation

```
Full documentation: DATASETS.md in the repo
(https://github.com/manojmallick/find-evil/blob/main/DATASETS.md)

Datasets used:
1. Synthetic injection test (ships in repo, runs anywhere) — a crafted case with 5
   known IOCs as ground truth, used to validate the scoring math and the 0%-
   hallucination guarantee end-to-end. Ground truth: tests/benchmark/ground_truth/synthetic.json
2. NIST CFReDS "Hacking Case" (cfreds.nist.gov, free) — Windows XP disk image;
   ground truth from NIST case notes. Requires SIFT + mounted image.
3. SANS 508 starter case — Windows disk + memory dump (the only set with memory,
   so it exercises the disk-vs-memory discrepancy detection).

Evidence integrity protocol: images mounted read-only (ro,noatime); SHA256 recorded
at analysis time and re-checked (spoliation detection); tool output never written to
evidence paths; only synthetic/disposable data used for destructive bypass testing.
```

---

## FIELD: Accuracy Report

```
Full report: ACCURACY_REPORT.md in the repo
(https://github.com/manojmallick/find-evil/blob/main/ACCURACY_REPORT.md)

Status of numbers (honesty policy):
- Synthetic dataset — REAL, reproducible now: precision 0.80, recall 0.80,
  0% CONFIRMED-tier hallucination (one IOC deliberately missed so the harness
  proves it can score a miss, and one benign LOLBIN correctly kept in the INFERRED
  tier, not CONFIRMED). Reproduce: python3 tests/benchmark/run_benchmark.py --dataset synthetic
- NIST CFReDS / SANS starter — marked PENDING a real SIFT run. We do not publish
  numbers we have not measured.

Hallucination definition + enforcement: a CONFIRMED finding with no traceable
call_id is rejected by the report generator (reports/generator.py), not asked about
in a prompt. Locked in by tests/unit/test_report_integrity.py and re-asserted by the
benchmark. This guarantee holds even in autonomous LLM mode
(tests/unit/test_reasoning.py proves an LLM-invented call_id is rejected).

False-positive handling: benign admin tools (certutil, psexec) are kept INFERRED
with a confidence score, never CONFIRMED; network findings filter known-good/private
IP ranges to suppress false positives.
```

---

## After all fields → "Add video" step
Paste your **YouTube (Unlisted)** link. Title/description for the video are in
`docs/YOUTUBE.md`.
```
