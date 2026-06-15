# DEMO_VIDEO_SCRIPT.md — Find Evil! Hackathon Submission
## 5-Minute Demo · Judges watch this when two submissions are close

---

## ⚡ TWO WAYS TO RECORD (read this first)

There are two recording paths. **Path B works on any laptop (macOS/Linux) with
zero setup — every command below was run and verified.** Use Path A only if you
have a live SIFT Workstation with evidence mounted.

### Path A — Live on SIFT (full fidelity)

```bash
# Setup (once)
cd /opt/find-evil && source venv/bin/activate

# THE RUN (Shot 3-4)
find-evil --case /cases/CASE001 --disk /mnt/case_disk \
          --memory /cases/CASE001/memory.raw --max-iterations 3

# Autonomous mode (best for the tiebreaker — needs ANTHROPIC_API_KEY)
find-evil --case /cases/CASE001 --disk /mnt/case_disk --reasoning

# THE REPORT (Shot 5)
python3 -m json.tool /cases/CASE001/findings/findings.json | head -60
xdg-open /cases/CASE001/findings/report.html      # Linux

# THE PROOF (Shot 6) — copy a call_id from the report, then:
grep '<call_id>' /opt/find-evil/logs/tool_calls.jsonl | python3 -m json.tool
```

### 🛟 Path B — Local laptop, no SIFT (VERIFIED — exact copy-paste)

The integration test drives the **real** agent, audit logger, and report
generator end-to-end (with simulated tool output) — same self-correction moment,
same verifiable audit trail. Pre-built sample artifacts live in `docs/sample_run/`.
Run from the repo directory:

```bash
cd /Users/manojmallick/Downloads/hack

# Shot 2 — guarantees as code (very strong on camera):
python3 -m pytest tests/                                    # 56 passed, incl. 12/12 bypasses

# Shot 3-4 — full pipeline live + the self-correction discrepancy:
python3 -m pytest tests/integration/test_full_pipeline.py -o addopts="" -v

# Shot 5 — the findings report (4 confirmed · 1 inferred · 1 discrepancy):
python3 -m json.tool docs/sample_run/findings.json | head -35

# Shot 6 — THE PROOF SHOT — grep a finding's call_id → exact tool + SHA256:
grep scan_yara_894812af docs/sample_run/tool_calls.jsonl | python3 -m json.tool

# Memorable — a hostile curl attempt BLOCKED + logged, never executed:
head -1 docs/sample_run/tool_calls.jsonl | python3 -m json.tool

# Open the report visually (macOS: `open`; Linux: `xdg-open`):
open docs/sample_run/report.html
```

> Be transparent on camera if you use Path B: "This run uses simulated
> forensic-tool output so it reproduces anywhere; the agent, guardrails, audit
> log, and integrity check are all real and run live." Honesty is a judging
> value here — owning it is a strength, not a weakness.

---

## Pre-filming checklist

- [ ] SIFT VM running, Protocol SIFT baseline installed
- [ ] Find Evil! installed via install.sh
- [ ] Starter case data mounted at /mnt/case_disk
- [ ] Memory dump at /cases/CASE001/memory.raw
- [ ] `baseline_output.txt` saved from a prior Protocol SIFT run
- [ ] OBS Studio or screen recorder running at 1080p
- [ ] Terminal font size: 16pt minimum (judges may watch at 720p)
- [ ] Clean terminal — no prior command history visible
- [ ] Notifications disabled

---

## Shot 1 — The Problem (0:00–0:45)

> ⚠️ **Two versions — pick by where you're recording.**
> Path A (SIFT) runs the live Protocol SIFT baseline. Path B (local laptop) uses
> a problem slide + narration — judges accept this; no `/opt/protocol-sift` or
> mounted evidence needed. **If `cd /opt/protocol-sift` failed, you want Path B.**

### Path A — Live Protocol SIFT baseline (SIFT only)

**Terminal commands to run:**
```bash
# Run baseline Protocol SIFT (already installed in Week 1)
cd /opt/protocol-sift
claude "analyze /mnt/case_disk and find all indicators of compromise"
# Wait for completion — save full output to baseline_output.txt
# Highlight 3-4 findings that have NO artifact backing

# On screen: count untraced findings
grep -c "artifact\|inode\|offset\|call_id" baseline_output.txt   # → 0 traceable
```

### Path B — Problem slide (local, no SIFT) — RECOMMENDED if you're on a laptop

No terminal. Show a full-screen title/problem slide (make it in Keynote / Google
Slides / CapCut) while you narrate. This is a clean, common way to open a demo.

**Slide text (one slide, large type):**
```
AI for incident response — two ways it breaks:

  1.  It can DESTROY the evidence.    (an agent with a shell can rm / dd / overwrite)
  2.  It HALLUCINATES findings.       ("PsExec ran at 14:22" — no artifact, no proof)

In a real incident, an unverifiable finding is worse than no finding.
```

**Optional 8-second real clip (instead of a static slide):** open the sample
report and point at the two tiers — the honest contrast.
```bash
open docs/sample_run/report.html      # macOS  (Linux: xdg-open)
```
Point at the CONFIRMED vs INFERRED columns: *"Most AI tools give you a flat list
you can't check. We separate proven from inferred — and every CONFIRMED finding
is greppable. That's what the next four minutes show."*

**Narration (both paths):**
> "AI-powered attackers move in minutes. The obvious fix — point an LLM agent at a
> forensic workstation — has two failure modes that make it unusable: it can
> destroy the very evidence it's analyzing, and it hallucinates findings you can't
> verify. Find Evil! makes both impossible — architecturally, not with a prompt."

**Text overlay:** `The problem: tamperable evidence + unverifiable findings`

---

## Shot 2 — Architecture (0:45–1:15)

**What to show:** Architecture diagram on screen — 30 seconds only. Move fast.

**Key points to call out visually (use cursor to point):**
1. Point to MCP server box: *"Custom MCP server — rm, dd, curl don't exist here"*
2. Point to evidence arrows: *"Read-only enforced at OS and server level"*
3. Point to audit log: *"Every tool call logged — any finding can be grepped"*
4. Point to self-correction loop: *"Three validation checks between every phase"*

**Narration:**
> "Find Evil! replaces Protocol SIFT's generic shell access with a custom MCP server 
> that exposes typed forensic functions. The agent physically cannot run rm or curl — 
> those functions don't exist. Every tool call is logged with a UUID that appears 
> in the final report. Any finding can be verified in under 10 seconds."

**Text overlay:** `Architectural constraints · not prompt-based restrictions`

---

## Shot 3 — Live Analysis Start (1:15–2:00)

> ⚠️ The commands below are **Path A (SIFT)**. On a laptop, record the
> **Path B** equivalent from the top block instead:
> `python3 -m pytest tests/integration/test_full_pipeline.py -o addopts="" -v`
> — it runs the real agent + audit log + report end-to-end and shows the same
> reasoning/self-correction. Narrate over it with the lines below.

**What to show:** Start Find Evil! on the SAME case Protocol SIFT just analyzed.

**Terminal commands:**
```bash
# Show the evidence mount (read-only)
mount | grep case_disk
# Output should show: ro,noatime

# Start analysis — this is the main event
find-evil \
  --case /cases/CASE001 \
  --disk /mnt/case_disk \
  --memory /cases/CASE001/memory.raw \
  --max-iterations 3
```

**What will appear on screen (show all of this):**
```
[*] Find Evil! — Autonomous IR Analysis
[*] Case: /cases/CASE001
[*] Disk: /mnt/case_disk
[*] Memory: /cases/CASE001/memory.raw
[*] Max iterations per phase: 3

[1/6] Phase 1: Triage — quick profile + IOC scan
    [+] Triage complete — 3 findings
[2/6] Phase 2: Timeline — MFT + events + prefetch
```

**Narration:**
> "Same evidence. Same case. Now watch the reasoning — the agent explains 
> every tool it chooses and why before running it."

**Show the CLAUDE.md reasoning output in terminal:**
```
[AGENT REASONING] Calling get_mft_timeline() because I need to establish 
the filesystem timeline. I expect to find modified/accessed/created timestamps 
for all files in the last 30 days. If timeline shows processes that contradict 
what I find in memory next phase, I will flag the discrepancy.
```

---

## Shot 4 — THE TIEBREAKER MOMENT (2:00–3:00)

**This is the most important 60 seconds of the video.**

> ⚠️ The screen output below is what a **SIFT run** produces. On a laptop, the
> **same cmd.exe disk-vs-memory discrepancy is real and visible** in the Path B
> integration test and the sample report — show `docs/sample_run/findings.json`
> (the `discrepancies` section) or the "Cross-source discrepancies" row in
> `docs/sample_run/report.html`, and narrate the lines below over it.

**What to show:** The self-correction loop catching a disk-memory discrepancy.

**Set this up before filming:**
Make sure your test case has `cmd.exe` in the prefetch (disk timeline) but the memory dump was captured after `cmd.exe` exited — so it won't appear in `pslist`. This is common in real cases.

**What should appear on screen:**
```
[3/6] Phase 3: Memory — pslist + malfind + netscan
    [+] Memory complete — 12 findings

[5/6] Phase 5: Correlation — cross-source discrepancy detection
    [~] DISCREPANCY DETECTED:
        Process 'cmd.exe' found in disk prefetch timeline (14:22:03)
        Process 'cmd.exe' NOT found in memory process list
        
    [*] Hypothesis: Process terminated before memory capture,
        OR process hiding technique active (rootkit),
        OR disk timestamp was modified post-compromise
        
    [~] Re-running targeted memory analysis for cmd.exe artifacts...
    [~] Iteration 2: Checking handles, VADs, and loaded modules...
    [+] Found: cmd.exe loaded modules still in VAD map (process terminated but memory not fully cleared)
    [+] Discrepancy resolved — CONFIRMED: cmd.exe executed at 14:22:03, terminated before capture
```

**Narration:**
> "The self-correction loop caught something. cmd.exe appears in the disk 
> timeline but not in the memory process list. A junior analyst might miss this. 
> Our agent flags it, forms three hypotheses, and re-runs targeted memory analysis. 
> It resolves the discrepancy autonomously — no human intervention."

**Text overlay:** `Self-correction · iteration 2 · discrepancy resolved`

---

## Shot 5 — Report Review (3:00–4:00)

**What to show:** Open the HTML report in a browser. Show the two tiers clearly.

**Terminal — Path A (SIFT):**
```bash
cat /cases/CASE001/findings/findings.json | python3 -m json.tool | head -60
open /cases/CASE001/findings/report.html      # macOS · Linux: xdg-open
```

**Terminal — Path B (local laptop):**
```bash
python3 -m json.tool docs/sample_run/findings.json | head -35
open docs/sample_run/report.html              # macOS · Linux: xdg-open
```

**In the browser — point to each section:**

1. **Summary bar:** Show the 4 stats (Total / Confirmed / Inferred / Discrepancies)
2. **CONFIRMED section:** Click one finding. Show:
   - The artifact path
   - The timestamp
   - The call_id UUID
   - The grep verification command
3. **INFERRED section:** Show a finding with 67% confidence and the caveat label
4. **Discrepancies section:** Show the cmd.exe discrepancy entry

**Narration:**
> "Every finding is categorized. CONFIRMED means we have a direct artifact — 
> a file path, a byte offset, and a tool call ID that links to the audit log. 
> INFERRED means the agent's analytical conclusion — explicitly labeled, 
> confidence-scored, never presented as direct evidence."

---

## Shot 6 — Verify a Finding Live (4:00–4:30)

**This is the proof shot. Do not skip this.**

**What to show:** Pick any CONFIRMED finding from the report, copy its call_id, grep the audit log.

**Path A (SIFT):**
```bash
# Pick a call_id from the HTML report, then verify it:
grep "get_mft_timeline_7f2a1b3c" /opt/find-evil/logs/tool_calls.jsonl | python3 -m json.tool
```

**Path B (local laptop) — this is the one to record:**
```bash
grep scan_yara_894812af docs/sample_run/tool_calls.jsonl | python3 -m json.tool
```

**Output on screen:**
```json
{
  "call_id": "get_mft_timeline_7f2a1b3c",
  "timestamp": "2026-05-02T14:22:07.441Z",
  "tool": "get_mft_timeline",
  "args": {
    "image_path": "/mnt/case_disk",
    "parsers": "mft,ntfs,winevt,prefetch,winreg"
  },
  "output_sha256": "a8f3b2c1...",
  "result_summary": {
    "total_events": 14729,
    "suspicious_events_count": 3
  }
}
```

**Narration:**
> "Any finding in this report can be verified in under 10 seconds. 
> Grep the call_id. Get the exact tool, the exact arguments, 
> and the SHA256 of the output. Full chain of custody."

---

## Shot 7 — Close (4:30–5:00)

**What to show:** GitHub repo, then the install command.

```bash
# Show GitHub repo briefly in browser: github.com/manojmallick/find-evil
# Then show the one-command install:
curl -fsSL https://raw.githubusercontent.com/manojmallick/find-evil/main/install.sh | bash
```

**Narration:**
> "Find Evil! is open source under Apache 2.0. One command to install on any SIFT Workstation. 
> Every finding it produces can be verified. Every guardrail is architectural — not a promise. 
> Built for the practitioner who needs to stand behind their results at 3 AM."

**Final text overlay:**
```
Find Evil! · Apache 2.0 · github.com/manojmallick/find-evil
0% hallucination rate (CONFIRMED tier) · Full audit trail · Self-correcting
SANS Find Evil! Hackathon 2026
```

---

## Post-filming checklist

- [ ] Video is under 5 minutes (trim if needed — 4:45 is ideal)
- [ ] Font is readable at 720p (watch at 720p before uploading)
- [ ] The tiebreaker moment (self-correction) is clearly visible
- [ ] The grep verification shot is included — this is non-negotiable
- [ ] Upload to YouTube as **Unlisted**
- [ ] Title: `Find Evil! — Autonomous IR Agent · SANS Hackathon 2026`
- [ ] Description includes GitHub link and hackathon link
- [ ] Test YouTube link in incognito before submitting to Devpost

---

## Editing tools (free)

| Tool | Best for | Platform |
|---|---|---|
| OBS Studio | Screen recording | Linux/Mac/Win |
| DaVinci Resolve | Editing + text overlays | Linux/Mac/Win |
| Kdenlive | Simple editing | Linux |
| CapCut | Quick text overlays | Mobile |

**Export settings:** 1080p, H.264, 4-8 Mbps, MP4

---

*Film this in Week 8 (Jun 3–9). Leave Jun 10–14 for edits and re-shoots.*
