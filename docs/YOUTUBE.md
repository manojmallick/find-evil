# 📺 YouTube — Title, Description, Voiceover

Copy-paste for the YouTube upload form. Upload as **Unlisted**, then put the link
in your Devpost submission.

---

## TITLE (pick one)

**Recommended:**
```
Find Evil! — Autonomous IR Agent You Can Verify | SANS Find Evil! Hackathon 2026
```

Alternates:
```
Find Evil! — An AI Forensics Agent That Physically Can't Tamper With Evidence
Find Evil! — 0% Hallucination, Full Audit Trail | SANS Find Evil! Hackathon 2026
Find Evil! — Autonomous Incident Response with Architectural Guardrails
```

---

## DESCRIPTION (paste as-is)

```
Find Evil! is an autonomous incident-response agent for the SANS SIFT Workstation
that you can actually trust. It analyzes disk and memory evidence the way a senior
analyst does — sequencing tools, recognizing anomalies, and self-correcting —
while making two things ARCHITECTURALLY impossible, not just discouraged:

  • Evidence tampering — the agent has no shell. rm, dd, curl, ssh do not exist
    in its tool surface. Destructive/exfil commands are blocked in code before any
    process spawns.
  • Hallucinated findings — every CONFIRMED finding must carry a tool call_id that
    is present in the audit log, or the report refuses to generate it. 0%
    hallucination in the CONFIRMED tier, by construction.

Any finding can be verified in under 10 seconds: grep its call_id against the
audit log and get the exact tool, the exact arguments, and the SHA256 of the
output that produced it. Full chain of custody.

⏱️ Chapters
0:00  The problem — tamperable evidence + unverifiable findings
0:35  Architecture — typed tools, three guardrails, all in code
1:05  The guarantees as code — 56 tests, 12/12 bypass attempts blocked
1:45  Full pipeline + self-correction (disk vs memory discrepancy)
2:35  The findings report — CONFIRMED vs INFERRED tiers
3:10  THE PROOF SHOT — verify any finding via its call_id
3:40  A hostile curl attempt blocked + logged · close

🔧 What's inside
• Custom MCP server exposing 10 typed forensic tools (timeline, prefetch, memory
  pslist/malfind/netscan, registry, event logs, YARA, timestomping)
• Deterministic 6-phase pipeline AND an autonomous LLM reasoning mode — the
  architectural guarantees hold in both
• Append-only JSONL audit log (call_id + SHA256 per tool call)
• Report generator that rejects any untraceable CONFIRMED finding
• 20 custom YARA rules · 56 automated tests · reproducible accuracy benchmark

🔗 Links
GitHub (Apache 2.0): https://github.com/manojmallick/find-evil
Hackathon: https://findevil.devpost.com

🛠️ Built with
Python 3.11 · custom MCP server (FastMCP) · Anthropic Claude (autonomous mode) ·
SANS SIFT tooling (log2timeline/plaso, Volatility 3, RegRipper, YARA)

Note on this recording: tool output is simulated so the demo reproduces on any
machine — but the agent, the guardrails, the audit log, and the integrity check
are all real and running live. Honesty over polish.

#DFIR #IncidentResponse #DigitalForensics #AI #LLM #Cybersecurity #SANS #SIFT #MCP
```

---

## FULL VOICEOVER (read straight through — ~4 min)

> **[Problem slide]** AI-powered attackers move in minutes. The obvious fix —
> point an AI agent at a forensic workstation — breaks two ways: the agent can
> destroy the very evidence it's analyzing, and it hallucinates findings you
> can't verify. Find Evil! makes both impossible — architecturally, not with a
> prompt.

> **[Architecture]** The agent reaches the operating system only through typed
> forensic tools. rm, dd, curl, ssh don't exist in its world. Every tool call is
> logged with a unique ID and a SHA256. And the report refuses to print any
> "confirmed" finding it can't trace back to a real tool call. Three independent
> guardrails — all enforced in code.

> **[Tests]** Every guarantee is backed by tests. Fifty-six of them — including
> twelve documented bypass attempts: injection, command-chaining, exfiltration.
> All blocked, all green. These aren't promises; they're regression tests.

> **[Pipeline]** Here's the agent running a full case — six phases, from triage
> to report. Watch the key moment: cmd.exe appears in the disk timeline but not
> in the memory process list. The agent flags that discrepancy, forms three
> hypotheses, and re-runs targeted analysis to resolve it — autonomously. That
> cross-source reasoning is what a senior analyst does. And this run uses
> simulated tool output so it reproduces anywhere — but the agent, guardrails,
> audit log, and integrity check are all real and live.

> **[Report]** Every finding is tiered. CONFIRMED means a direct artifact with a
> tool call ID. INFERRED means an analytical conclusion — confidence-scored,
> never dressed up as hard evidence. Four confirmed, one inferred, one
> discrepancy — and zero untraceable findings.

> **[Proof shot]** This is the proof. Take any confirmed finding, grep its call
> ID against the audit log, and you get the exact tool, the exact arguments, and
> the SHA256 of the output that produced it. Any finding, verified in under ten
> seconds. Full chain of custody.

> **[Blocked + close]** And here's a hostile curl exfiltration attempt — logged,
> but never executed. The guardrail caught it before any process spawned. Find
> Evil! is open source under Apache 2.0. Every finding is verifiable. Every
> guardrail is architectural — not a promise. Built for the analyst who has to
> stand behind their results at 3 AM.

---

## NOTES
- Timestamps are for a ~4:00 cut — **adjust the chapter times after you edit** so
  they match your actual video (the first chapter must stay `0:00`).
- Keep the title under ~70 characters so it doesn't truncate in search.
- Thumbnail: use `assets/cover.png`.
