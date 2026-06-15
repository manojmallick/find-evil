# Find Evil! — Devpost Project Description

> Paste this into the Devpost "Project Description" field. Trim to taste; the
> section headers match how Devpost judges typically scan a submission.

---

## Inspiration

AI-powered adversaries operate in minutes. Human responders are still pulling up
their toolkit. The obvious fix — point an LLM agent at a forensic workstation and
let it rip — has two failure modes that make it unusable for real casework:

1. **It can destroy the evidence.** An agent with shell access can `rm`, `dd`, or
   overwrite the very disk image it's analyzing. Worse, evidence is *untrusted
   input* — an attacker can plant a prompt-injection payload in a file, and the
   agent reads it.
2. **It hallucinates findings.** "The attacker used PsExec at 14:22" — with no
   artifact, no offset, no way to verify. In a real incident, an unverifiable
   finding is worse than no finding: it wastes the one resource you don't have,
   analyst time, at 3 AM.

We built Find Evil! to prove both problems are solvable **architecturally** —
not with a longer system prompt, but by making the bad outcomes structurally
impossible.

## What it does

Find Evil! is an autonomous incident-response agent for the SANS SIFT
Workstation. Point it at a mounted disk image (and optionally a memory dump) and
it runs a six-phase analysis the way a senior analyst would:

1. **Triage** — chain-of-custody hash + YARA IOC sweep (20 custom rules)
2. **Timeline** — MFT + prefetch (what executed, when)
3. **Memory** — Volatility process list (what was live at capture)
4. **Artifacts** — registry persistence + logon event logs
5. **Correlation** — cross-source discrepancy detection + self-correction
6. **Report** — a two-tier, fully-verifiable findings report

It produces a report where **every CONFIRMED finding can be verified in under ten
seconds** by grepping one ID against an audit log — returning the exact tool, the
exact arguments, and the SHA256 of the output that produced it.

## The two things that make it different

**1. Architectural constraints, not prompt-based ones.**
The agent has no shell. It reaches the OS only through a custom MCP server that
exposes seven *typed* forensic functions. `rm`, `dd`, `curl`, `wget`, `ssh`,
`shred` are not "discouraged" — they do not exist in the agent's world. Three
independent layers enforce this, all in code, before any process spawns:
- typed tool surface (the destructive verbs are simply absent)
- Pydantic path/injection validation
- a `_safe_run()` chokepoint that screens every command and runs `shell=False`

We documented **12 bypass attempts** (injection, redirection, command chaining,
prompt injection from planted payloads) in `BYPASS_TESTING.md`. All 12 are
blocked — and we turned each into a passing unit test, so the guarantee can't
silently regress.

**2. A 0% hallucination rate in the CONFIRMED tier — by construction.**
Findings come in two tiers. CONFIRMED findings *must* carry a `call_id` that
exists in the audit log; the report generator refuses to emit a CONFIRMED
finding it can't trace, raising an integrity error instead. INFERRED findings are
analytical conclusions — always confidence-scored, never dressed up as direct
evidence. The hallucination guarantee is enforced in `reports/generator.py` and
locked in by tests.

## How we built it

- **Language:** Python 3.11
- **Tool layer:** a custom MCP server (FastMCP) wrapping SIFT tooling —
  log2timeline/plaso, Volatility 3, RegRipper, YARA
- **Agent:** a deterministic six-phase orchestrator with a bounded
  self-correction loop. We chose deterministic sequencing over a free-roaming
  LLM *on purpose*: a fixed pipeline over audited tools is more reproducible and
  more defensible in court than letting a model improvise shell commands. The
  analyst reasoning (sequencing, anomaly recognition, self-correction) is in the
  control flow, not hidden in a prompt.
- **Integrity:** an append-only JSONL audit log; every tool call (executed *or*
  blocked) gets a UUID and a SHA256 of its output.
- **Quality bar:** 47 automated tests + a reproducible accuracy benchmark that
  runs with no evidence required.

## The self-correction moment (our tiebreaker demo)

A process appears in the disk prefetch timeline (it executed) but is absent from
the memory process list (it's not running). A junior analyst might miss it. Find
Evil! flags the discrepancy, forms three hypotheses — terminated before capture,
process-hiding rootkit, or post-compromise timestomping — and re-runs targeted
memory analysis to resolve it. Autonomously. It's the kind of cross-source
reasoning the hackathon asks for, and it's visible live in the demo.

## Accuracy & honesty

Per the hackathon's "honesty over perfection" rule, our `ACCURACY_REPORT.md` is
explicit about what's measured vs. pending:
- **Synthetic dataset (real, runs anywhere):** precision 0.80, recall 0.80,
  **0% CONFIRMED-tier hallucination** — including one deliberately-missed IOC so
  the harness proves it can score a miss, not just report 100%.
- **NIST CFReDS / SANS starter cases:** clearly marked *pending a real SIFT run*.
  We do not publish numbers we have not measured.

## Challenges we ran into

- **Injection through tool arguments**, not just the command line — a
  `parsers="mft; rm /cases/x"` argument. Solved with argument-level screening
  *plus* `shell=False`, so even an unscreened payload is an inert string.
- **Defining "hallucination" rigorously** enough to enforce in code. The answer:
  traceability to a logged `call_id`, checked at report-generation time.
- **Resisting the temptation to fake the demo numbers.** We built a synthetic,
  fully-known dataset instead, so the metrics are real and reproducible.

## Accomplishments we're proud of

- 12/12 documented bypasses blocked, each as a regression test.
- A hallucination guarantee that's mechanically enforced, not promised.
- A report where any finding is verifiable in <10 seconds.
- 47 passing tests and a one-command install.

## What's next

- Timestomping detection (`$STANDARD_INFORMATION` vs `$FILE_NAME`).
- macOS/Linux artifact phases (currently Windows-focused).
- An optional LLM narration layer over the deterministic floor, for analysts who
  want natural-language reasoning without giving up the audit guarantees.

## Try it

```bash
git clone https://github.com/YOUR_USERNAME/find-evil.git && cd find-evil
python3 -m pytest tests/                                  # 47 passed
python3 tests/benchmark/run_benchmark.py --dataset synthetic
```

Built for the SANS Find Evil! Hackathon 2026 · Apache 2.0 · evidence integrity
is the product.
