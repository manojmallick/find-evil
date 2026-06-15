# CASE — Find Evil! Analysis Directives

> Copy this file into each new case directory:
> `cp /cases/TEMPLATE/CLAUDE.md /cases/CASE001/CLAUDE.md`
> It tells the autonomous agent how to behave on THIS case. Edit the case
> metadata block before running.

---

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CASE001` |
| Analyst | `[YOUR NAME]` |
| Opened | `[DATE]` |
| Evidence (disk) | `/mnt/case_disk` (mounted read-only) |
| Evidence (memory) | `/cases/CASE001/memory.raw` (optional) |
| Authorisation | `[ticket / legal authority]` |

---

## Rules of engagement (non-negotiable)

1. **Evidence is read-only.** Never write to `/cases`, `/mnt`, or `/media`.
   The MCP server enforces this architecturally — but treat it as sacred anyway.
2. **Every CONFIRMED finding must cite a `call_id`.** If you cannot trace a
   claim to a tool call in `tool_calls.jsonl`, it is at most INFERRED.
3. **Label uncertainty honestly.** Use the INFERRED tier with a confidence
   score for analytical conclusions. Do not present inference as artifact.
4. **Surface discrepancies, don't hide them.** If disk and memory disagree,
   flag it, form hypotheses, and re-analyze — do not paper over it.
5. **No external network.** curl/wget/ssh are not available to you by design.

---

## Analysis plan (6 phases)

1. **Triage** — `get_disk_hash` (chain of custody) + `scan_yara` (IOC sweep).
2. **Timeline** — `get_mft_timeline` + `extract_prefetch` (execution evidence).
3. **Memory** — `run_volatility_pslist` (skip if no memory image).
4. **Artifacts** — `get_registry_key` (persistence) + `get_event_logs` (logons).
5. **Correlation** — cross-source discrepancy detection + self-correction
   (bounded by `--max-iterations`).
6. **Report** — verify all `call_id`s against the audit log, then render
   `findings/findings.json` and `findings/report.html`.

---

## What good output looks like

- A CONFIRMED finding names the artifact path, the event time (from the
  evidence, not the clock), and the `call_id` to grep.
- An INFERRED finding names its confidence and the call_ids that support it.
- Discrepancies are listed even when resolved, with the hypotheses considered.

---

## Run

```bash
find-evil --case /cases/CASE001 --disk /mnt/case_disk \
         --memory /cases/CASE001/memory.raw --max-iterations 3
```

Verify any finding:

```bash
grep '<call_id from report>' /opt/find-evil/logs/tool_calls.jsonl | python3 -m json.tool
```

---

*Find Evil! · Apache 2.0 · evidence integrity is the product*
