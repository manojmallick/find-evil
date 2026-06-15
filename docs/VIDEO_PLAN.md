# 🎬 Find Evil! — Video Plan (LOCAL / Path B only)

**One path. No SIFT. No confusion.** Everything here runs on your Mac and was
verified working. Target length: **~4:00** (under the 5:00 limit).

The whole live portion is one script — `demo.sh` — that pauses between shots so
you narrate, then press **Enter** to advance. You only make 2 slides (open +
close); everything else is the script.

---

## ✅ Before you hit record (5 minutes)

1. **Terminal:** font size **16pt+**, then run `clear` (no command history on screen).
2. **Notifications off** (macOS: Focus / Do Not Disturb).
3. **Make 2 slides** (Keynote / Google Slides / Canva) — text is in this doc below.
4. **Screen recorder:** QuickTime (⌘⇧5 → Record Entire Screen) or OBS, 1080p.
5. **Dry-run once:** `cd /Users/manojmallick/Downloads/hack && bash demo.sh`
   (press Enter through it once so you know the rhythm). Then `clear` and record.

---

## The recording flow (7 beats, ~4 min)

### ▶ BEAT 1 — Problem slide  (0:00 – 0:35)   *[SLIDE, no terminal]*

Show **Slide 1** full screen. Narrate:

> "AI-powered attackers move in minutes. The obvious fix — point an AI agent at a
> forensic workstation — breaks two ways: the agent can **destroy the evidence**
> it's analyzing, and it **hallucinates findings** you can't verify. Find Evil!
> makes both impossible — architecturally, not with a prompt."

**Slide 1 text:**
```
FIND EVIL!
Autonomous incident response you can actually trust

AI for forensics breaks two ways:
   1.  It can DESTROY the evidence   (a shell agent can rm / dd / overwrite)
   2.  It HALLUCINATES findings      ("PsExec ran at 14:22" — no proof)

We make both architecturally impossible.
```

---

### ▶ BEAT 2 — Architecture  (0:35 – 1:05)   *[IMAGE, no terminal]*

Show the image **`assets/architecture.png`** (open it / drop it on a slide).
Point with your cursor and narrate:

> "The agent reaches the OS only through typed forensic tools. `rm`, `dd`, `curl`,
> `ssh` don't exist in its world. Every tool call is logged with a UUID and a
> SHA256. And the report refuses to print any 'confirmed' finding it can't trace
> back to a real tool call. Three independent guardrails, all enforced in code."

**Overlay:** `Architectural constraints — not prompt-based restrictions`

---

### ▶ Now start the script:  `bash demo.sh`

From here, run **one command** and narrate at each pause:

```bash
cd /Users/manojmallick/Downloads/hack
bash demo.sh
```

---

### ▶ BEAT 3 — Guarantees as code  (1:05 – 1:45)   *[demo.sh "SHOT 2"]*

The script runs the test suite. While `56 passed` is on screen:

> "Every guarantee is backed by tests. Fifty-six of them — including twelve
> documented bypass attempts: injection, command-chaining, exfiltration. All
> blocked, all green. These aren't promises; they're regression tests."

**Overlay:** `56 tests · 12/12 bypass attempts blocked`
→ Press **Enter**.

---

### ▶ BEAT 4 — The pipeline + self-correction  (1:45 – 2:35)   *[demo.sh "SHOT 3-4"]*

The integration test runs the real agent end-to-end. While it passes:

> "Here's the agent running a full case. Six phases — triage, timeline, memory,
> artifacts, correlation, report. The key moment: `cmd.exe` shows up in the disk
> timeline but **not** in the memory process list. The agent flags that
> discrepancy, forms three hypotheses, and re-runs targeted analysis to resolve
> it — autonomously. That cross-source reasoning is what a senior analyst does."

**Overlay:** `Self-correction · disk vs memory discrepancy · resolved`
→ Press **Enter**.

---

### ▶ BEAT 5 — The report & two tiers  (2:35 – 3:10)   *[demo.sh "SHOT 5"]*

The findings JSON is on screen (4 confirmed · 1 inferred · 1 discrepancy):

> "Every finding is tiered. CONFIRMED means a direct artifact with a tool call ID.
> INFERRED means an analytical conclusion — confidence-scored, never dressed up as
> hard evidence. Look at the summary: four confirmed, one inferred, one
> discrepancy, and zero untraceable findings."

→ Press **Enter**.

---

### ▶ BEAT 6 — THE PROOF SHOT  (3:10 – 3:40)   *[demo.sh "SHOT 6"]*   ⭐ DO NOT SKIP

The script greps a finding's `call_id` and shows the audit record:

> "This is the proof. Take any confirmed finding, grep its call ID against the
> audit log — and you get the exact tool, the exact arguments, and the SHA256 of
> the output that produced it. Any finding, verified in under ten seconds. Full
> chain of custody."

**Overlay:** `Any finding → grep call_id → verified in <10s`
→ Press **Enter**.

---

### ▶ BEAT 7 — Blocked attack + close  (3:40 – 4:10)   *[demo.sh "BONUS" + Slide 2]*

The script shows the blocked `curl` audit entry:

> "And here's a hostile `curl` exfiltration attempt — logged, but never executed.
> The guardrail caught it before any process spawned."

Press **Enter** once more (the report opens in your browser — pan across it for a
second), then cut to **Slide 2** and close:

> "Find Evil! is open source under Apache 2.0. Every finding is verifiable. Every
> guardrail is architectural — not a promise. Built for the analyst who has to
> stand behind their results at 3 AM."

**Slide 2 text:**
```
FIND EVIL!
github.com/manojmallick/find-evil  ·  Apache 2.0

0% hallucination (CONFIRMED tier)  ·  Full audit trail  ·  Self-correcting
10 typed forensic tools  ·  56 tests  ·  12/12 bypasses blocked

SANS Find Evil! Hackathon 2026
```

---

## 🎙️ Honesty line (say it once, around Beat 3 or 4)

> "This run uses simulated forensic-tool output so it reproduces on any machine —
> but the agent, the guardrails, the audit log, and the integrity check are all
> real and running live."

Owning this is a **strength** — honesty is an explicit judging value.

---

## 📤 After recording

- [ ] Trim to **under 5:00** (4:00–4:30 ideal).
- [ ] Watch once at **720p** — is every line of text readable?
- [ ] The **proof shot (Beat 6)** is clearly visible — non-negotiable.
- [ ] Upload to **YouTube as Unlisted**.
- [ ] Title: `Find Evil! — Autonomous IR Agent · SANS Hackathon 2026`
- [ ] Description: GitHub link (`github.com/manojmallick/find-evil`) + hackathon link.
- [ ] Test the link in an incognito window before submitting.

---

## The only commands you type (in order)

```bash
# Beat 2: show the architecture image
open assets/architecture.png

# Beats 3–7: the whole live demo, one command, narrate at each pause
cd /Users/manojmallick/Downloads/hack
bash demo.sh
```

That's it. No `/opt`, no `/cases`, no `/mnt` — nothing that can fail.
