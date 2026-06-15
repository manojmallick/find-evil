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

banner "SHOT 5 — The findings report (4 confirmed · 1 inferred · 1 discrepancy)"
python3 -m json.tool docs/sample_run/findings.json | head -40
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
