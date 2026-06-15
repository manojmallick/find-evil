# Find Evil! — Architecture & Security Boundaries

This document is the architecture-diagram submission. It shows the data flow,
the components, and — most importantly for the judging criteria — the **trust
boundaries** where the architectural guarantees are enforced.

The central design claim: **the agent cannot tamper with evidence or exfiltrate
data because the capability to do so does not exist in its tool surface**, not
because it was told not to. Every boundary below is enforced in code, before any
subprocess spawns, and is covered by tests.

---

## System diagram (Mermaid — renders on GitHub)

```mermaid
flowchart TB
    subgraph UNTRUSTED["🔴 UNTRUSTED INPUT (evidence may contain attacker-planted payloads)"]
        EV["Disk image / Memory dump<br/>/mnt/case_disk, /cases/*.raw<br/>mounted READ-ONLY (ro,noatime)"]
    end

    subgraph AGENT["🟡 AGENT ZONE — no direct OS access"]
        LOOP["find-evil agent (agent/loop.py)<br/>6-phase pipeline + self-correction"]
    end

    subgraph BOUNDARY1["🛡️ BOUNDARY 1 — Typed tool surface (mcp_server/server.py + tools.py)"]
        TOOLS["7 typed tools ONLY:<br/>get_disk_hash · get_mft_timeline · get_event_logs<br/>extract_prefetch · get_registry_key · scan_yara · run_volatility_pslist<br/><br/>❌ rm · dd · curl · wget · ssh · shred — DO NOT EXIST"]
    end

    subgraph BOUNDARY2["🛡️ BOUNDARY 2 — Input validation (mcp_server/config.py)"]
        VAL["Pydantic path validation + injection screen<br/>validate_evidence_path() · assert_command_allowed()<br/>assert_no_protected_write()"]
    end

    subgraph BOUNDARY3["🛡️ BOUNDARY 3 — Guarded execution (mcp_server/safe_exec.py)"]
        SAFE["_safe_run(): BLOCKED_COMMANDS check →<br/>PROTECTED_WRITE_PATHS check → subprocess(shell=False)<br/>(shell disabled ⇒ injected metacharacters are inert)"]
    end

    subgraph TRUSTED["🟢 TRUSTED — SIFT forensic binaries (read-only ops)"]
        SIFT["log2timeline.py · psort.py · vol.py<br/>rip.pl · yara · prefetch.py"]
    end

    subgraph AUDIT["🟢 AUDIT & INTEGRITY (mcp_server/logger.py)"]
        LOG["tool_calls.jsonl<br/>call_id (UUID) + SHA256(output) + timestamp<br/>blocked attempts logged too"]
        HASH["evidence_hashes.json<br/>spoliation detection"]
    end

    subgraph REPORT["🟢 REPORT GENERATOR (reports/generator.py)"]
        GEN["verify_findings(): every CONFIRMED finding's<br/>call_id MUST exist in tool_calls.jsonl<br/>else IntegrityError — report refuses to generate"]
        OUT["findings.json + report.html"]
    end

    EV -->|read-only| TOOLS
    LOOP -->|"may ONLY call typed tools"| TOOLS
    TOOLS --> VAL
    VAL -->|"reject: bad path / injection"| BLOCKED1["⛔ BLOCKED + logged"]
    VAL --> SAFE
    SAFE -->|"reject: blocked cmd / protected write"| BLOCKED2["⛔ BLOCKED + logged"]
    SAFE -->|"validated argv, no shell"| SIFT
    SIFT -->|stdout| LOG
    SAFE --> LOG
    EV -.->|"hash at mount"| HASH
    LOG --> GEN
    GEN --> OUT
    OUT -.->|"each call_id greppable"| LOG

    BLOCKED1 --> LOG
    BLOCKED2 --> LOG
```

---

## Trust boundaries — what each one stops

| Boundary | Enforced in | Stops | Test |
|---|---|---|---|
| **1. Typed tool surface** | `tools.py`, `server.py` | The agent ever invoking `rm`/`dd`/`curl`/`ssh` — they are not registered tools | `test_full_pipeline.py` |
| **2. Input validation** | `config.py::validate_evidence_path`, `assert_command_allowed` | Path injection (`&&`, backticks), paths outside `/cases`,`/mnt`, traversal | `test_guardrails.py` (path cases) |
| **3. Guarded execution** | `safe_exec.py::_safe_run` + `config.py` | Blocked commands, writes to protected paths; `shell=False` neutralizes any injected metacharacters | `test_guardrails.py` (command + write cases) |
| **Audit & integrity** | `logger.py` | Untraceable actions — every call (executed *or* blocked) is logged with a SHA256 | `test_logger.py` |
| **Report integrity** | `generator.py::verify_findings` | Hallucinated CONFIRMED findings — no `call_id` in the log ⇒ report aborts | `test_report_integrity.py` |

---

## Layered view (ASCII fallback)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ LAYER 6 · INTERFACE        find-evil CLI  (agent/loop.py)                  │
├──────────────────────────────────────────────────────────────────────────┤
│ LAYER 5 · ORCHESTRATION    6-phase loop · self-correction · correlation    │
│                            Triage→Timeline→Memory→Artifacts→Correlate→Report│
├───────────────────────── 🛡️ TRUST BOUNDARY (agent ↔ OS) ──────────────────┤
│ LAYER 4 · TYPED TOOLS      mcp_server: 7 forensic tools, rm/dd/curl ABSENT  │
│ LAYER 3 · VALIDATION       Pydantic paths + injection screen (config.py)    │
│ LAYER 2 · GUARDED EXEC     _safe_run: BLOCKED_COMMANDS + PROTECTED paths     │
│                            subprocess(shell=False)  (safe_exec.py)           │
├──────────────────────────────────────────────────────────────────────────┤
│ LAYER 1 · TRUSTED TOOLS    SIFT binaries (read-only): log2timeline, vol...   │
├──────────────────────────────────────────────────────────────────────────┤
│ CROSS-CUTTING · AUDIT      tool_calls.jsonl (call_id + SHA256) · report     │
│                            generator verifies every CONFIRMED call_id        │
└──────────────────────────────────────────────────────────────────────────┘
        Evidence (/mnt, /cases) mounted READ-ONLY — writes rejected at L1, L2, L3
```

---

## Defense-in-depth: a single injection attempt, traced

Attacker plants `parsers = "mft; rm /cases/evidence.E01"` (via a tool argument):

1. **Boundary 2** — `_screen_aux_field` rejects the `;` character → `GuardrailError`.
2. *Even if it passed*, **Boundary 3** — `_safe_run` finds `rm` in `BLOCKED_COMMANDS` → rejected.
3. *Even if that passed*, the call runs with `shell=False`, so `; rm …` is a literal
   string argument to `log2timeline.py`, never a second command.
4. The blocked attempt is written to `tool_calls.jsonl` as `BLOCKED_ATTEMPT`.

Three independent layers, any one of which stops it. This is the "architectural,
not prompt-based" property the hackathon asks teams to demonstrate.

> To export a PNG for slides: paste the Mermaid block into https://mermaid.live
> and export, or run `mmdc -i ARCHITECTURE.md -o architecture.png` (mermaid-cli).
