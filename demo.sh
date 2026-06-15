#!/bin/bash
# Find Evil! — Local demo driver (no SIFT needed).
# Run from the repo:  bash demo.sh
# Press Enter to advance between shots while you narrate. Ctrl-C to stop.
#
# Every command here runs on a plain laptop — nothing touches /opt, /cases, /mnt.

set -u
cd "$(dirname "$0")"

BOLD=$'\033[1m'; CYAN=$'\033[0;36m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'

banner() { echo; echo "${CYAN}════════════════════════════════════════════════════════════${NC}";
           echo "${BOLD} $1${NC}";
           echo "${CYAN}════════════════════════════════════════════════════════════${NC}"; }
pause()  { echo; read -r -p "${GREEN}↵  Press Enter for the next shot...${NC}" _; clear; }

clear
banner "FIND EVIL! — live demo (local, no SIFT)"
echo "  Autonomous, audit-traced incident response."
echo "  Every CONFIRMED finding is traceable; the agent physically cannot"
echo "  tamper with evidence or exfiltrate data."
pause

banner "SHOT 2 — The guarantees, as code (56 tests, incl. 12/12 bypass blocks)"
python3 -m pytest tests/
pause

banner "SHOT 3-4 — Full pipeline live + the self-correction discrepancy"
python3 -m pytest tests/integration/test_full_pipeline.py -o addopts="" -v
pause

banner "SHOT 5 — The findings report (fits on one screen)"
python3 - <<'PY'
import json
d = json.load(open("docs/sample_run/findings.json"))
s = d["summary"]; integ = d.get("integrity", {})
print(f"  Case {d['case_id']}   disk={d['disk_path']}   memory={d['memory_path']}")
print(f"  {s['confirmed']} CONFIRMED   {s['inferred']} INFERRED   "
      f"{s['discrepancies']} DISCREPANCY   {s['iterations']} self-correction iterations")
print(f"  Untraceable CONFIRMED findings: {integ.get('untraceable_confirmed_findings', 0)}   (integrity check passed)")
print()
print(f"  {'ID':5} {'TIER':10} {'CATEGORY':22} {'CALL_ID':22} FINDING")
print("  " + "-" * 100)
for f in d["findings"]:
    cid = f["call_id"] or "(inferred — none)"
    print(f"  {f['id']:5} {f['tier']:10} {f['category']:22} {cid:22} {f['title'][:30]}")
print()
print("  Cross-source discrepancies:")
for x in d["discrepancies"]:
    print(f"   - {x['id']}  {x['summary'][:70]}  [resolved: {x['resolved']}]")
PY
pause

banner "SHOT 6 — THE PROOF SHOT: grep a finding's call_id -> exact tool + SHA256"
echo "${BOLD}\$ grep scan_yara_894812af docs/sample_run/tool_calls.jsonl${NC}"
echo
grep scan_yara_894812af docs/sample_run/tool_calls.jsonl | python3 -m json.tool
pause

banner "BONUS — A hostile 'curl' attempt BLOCKED + logged (never executed)"
echo "${BOLD}\$ head -1 docs/sample_run/tool_calls.jsonl${NC}"
echo
head -1 docs/sample_run/tool_calls.jsonl | python3 -m json.tool
pause

banner "SHOT 5b — Open the visual report (opens your browser)"
echo "Opening docs/sample_run/report.html ..."
if command -v open >/dev/null 2>&1; then open docs/sample_run/report.html
elif command -v xdg-open >/dev/null 2>&1; then xdg-open docs/sample_run/report.html
else echo "Open this file in a browser: $(pwd)/docs/sample_run/report.html"; fi
echo
echo "${GREEN}Demo complete.${NC} Repo: github.com/manojmallick/find-evil"
