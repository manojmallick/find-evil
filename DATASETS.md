# DATASETS.md — Find Evil! Test Data & Ground Truth

> Required submission: dataset documentation with testing sources.
> This describes every dataset we use, where it comes from, how ground truth is
> established, and exactly how to reproduce our numbers.

---

## Summary

| Dataset | Source | Type | License/Access | Ground truth | Runs without SIFT? |
|---|---|---|---|---|---|
| **Synthetic injection test** | Authored in this repo | Crafted, fully known | Apache 2.0 (ours) | Authored with the case | ✅ Yes |
| **NIST CFReDS Hacking Case** | [cfreds.nist.gov](https://cfreds.nist.gov) | Windows XP disk image | Free, public | NIST case notes | ❌ Needs mounted image |
| **SANS 508 Starter Case** | Hackathon starter data | Windows disk + memory | Provided to participants | Self-assessed + manual analysis | ❌ Needs mounted image |

We separate datasets by whether they can be scored **without** a SIFT Workstation
and mounted evidence. The synthetic set proves the *logic* (scoring math +
hallucination guarantee) anywhere; the real cases prove *field accuracy* and
require the actual images.

---

## 1. Synthetic injection test ✅ (primary, reproducible)

**Location:** `tests/benchmark/ground_truth/synthetic.json`
**Purpose:** Validate the benchmark math and the 0%-hallucination guarantee
end-to-end with a fully-known case, no external evidence required.

**Why synthetic?** For a hackathon judged on honesty, a fully-known case lets us
prove the *machinery* is correct (precision/recall computed properly, CONFIRMED
findings traced to real audit-log entries) without claiming field results we
haven't earned. It is explicitly **not** a substitute for real-evidence testing —
it's a unit test for the accuracy pipeline itself.

**Ground truth (5 planted IOCs):**

| ID | Category | Indicator | Maps to YARA rule |
|---|---|---|---|
| GT-1 | command_and_control | C2_Cobalt_Strike_Beacon | `C2_Cobalt_Strike_Beacon` |
| GT-2 | persistence | Run key | `Persistence_Registry_Run_Keys_Suspicious` |
| GT-3 | lateral_movement | Event 4648 | (event-log correlation) |
| GT-4 | defense_evasion | Timestomping | `Evasion_Timestomping_Indicator` |
| GT-5 | exfiltration | Archive_Staging | `Exfiltration_Archive_Staging` |

**How it's scored:** `tests/benchmark/run_benchmark.py` constructs a run whose
CONFIRMED findings reference real `call_id`s written to a temporary audit log,
then matches findings against the ground-truth IOCs (category + indicator
substring) to compute TP/FP/FN. The modelled run detects 4/5 IOCs (GT-5
deliberately missed) with one benign false positive, yielding precision 0.80 /
recall 0.80 / **0.0 hallucination rate**.

**Reproduce:**
```bash
python3 tests/benchmark/run_benchmark.py --dataset synthetic
```

---

## 2. NIST CFReDS Hacking Case ⏳ (real evidence)

**Source:** NIST Computer Forensic Reference Data Sets — the "Hacking Case"
([cfreds.nist.gov](https://cfreds.nist.gov)). Free and public.
**Evidence:** Windows XP disk image.
**Documented activity:** unauthorized access, tool installation, data staging.
**Ground truth:** NIST publishes case notes describing the artifacts and answers;
we encode the relevant IOCs into `tests/benchmark/ground_truth/nist-hacking.json`
(to be authored from the case notes before scoring — does not ship yet).

**Reproduce (on SIFT, image mounted read-only):**
```bash
sudo ewfmount nist_hacking.E01 /mnt/ewf/
sudo mount -o ro,loop,noatime /mnt/ewf/ewf1 /mnt/case_disk
python3 tests/benchmark/run_benchmark.py --dataset nist-hacking \
    --case /cases/NIST --disk /mnt/case_disk
```

**Status:** Pending a real run. We do not publish unmeasured numbers; see
`ACCURACY_REPORT.md`.

---

## 3. SANS 508 Starter Case ⏳ (real evidence)

**Source:** Hackathon starter data (provided to participants).
**Evidence:** Windows disk image + memory dump.
**Ground truth:** self-assessed through manual analysis; this is the case used
for the Protocol-SIFT-baseline vs Find-Evil! before/after comparison.
**Why it matters:** it's the only dataset with a **memory dump**, so it's the one
that exercises the cross-source (disk vs memory) discrepancy detection that
powers the self-correction demo.

**Reproduce (on SIFT):**
```bash
python3 tests/benchmark/run_benchmark.py --dataset starter-case \
    --case /cases/CASE001 --disk /mnt/case_disk \
    --memory /cases/CASE001/memory.raw
```

**Status:** Pending a real run.

---

## Evidence integrity protocol (all datasets)

1. **Mount read-only.** `ewfmount` + `mount -o ro,noatime`. Verified with
   `mount | grep case_disk`.
2. **Hash at mount time.** `get_disk_hash` records the SHA256 into
   `logs/evidence_hashes.json` (first-seen). A later mismatch is flagged
   `INTEGRITY_VIOLATION` — see `tests/unit/test_logger.py`.
3. **Never copy evidence to scratch.** Tool *output* goes to
   `/tmp/find-evil-output/`; evidence is never written anywhere.
4. **Synthetic/test data only for bypass testing.** Per `BYPASS_TESTING.md`, no
   real or production evidence is ever used to test destructive bypasses.

---

## Adding a new dataset

1. Author `tests/benchmark/ground_truth/<name>.json` with an `iocs` list of
   `{id, category, indicator}`.
2. Add `<name>` to the `--dataset` choices in `run_benchmark.py`.
3. Run with `--case/--disk[/--memory]` and commit the resulting
   `tests/benchmark/results/<name>_results.json`.

---

*All ground-truth files and benchmark code are open-sourced under Apache 2.0.*
