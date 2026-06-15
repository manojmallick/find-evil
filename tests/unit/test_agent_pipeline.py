# Find Evil! — Orchestrator / parser tests.
#
# Exercises the deterministic phase logic and the cross-source correlation that
# powers the demo's self-correction moment — without needing SIFT binaries.
#
# License: Apache 2.0

from __future__ import annotations

from agent import loop


# ── Output parsers ──────────────────────────────────────────────────────────
def test_parse_yara_matches():
    out = "C2_Cobalt_Strike_Beacon /mnt/case_disk/Windows/Temp/evil.exe\nnoise line\n"
    assert loop._parse_yara(out) == [
        ("C2_Cobalt_Strike_Beacon", "/mnt/case_disk/Windows/Temp/evil.exe")
    ]


def test_parse_processes_from_json():
    out = '[{"ImageFileName": "cmd.exe"}, {"ImageFileName": "explorer.exe"}]'
    assert loop._parse_processes(out) == {"cmd.exe", "explorer.exe"}


def test_parse_processes_from_text():
    out = "Prefetch: POWERSHELL.EXE-ABC.pf ran at ...\nCMD.EXE-DEF.pf ..."
    procs = loop._parse_processes(out)
    assert "powershell.exe" in procs and "cmd.exe" in procs


def test_yara_category_mapping():
    assert loop._yara_category("Persistence_Registry_Run_Keys_Suspicious")[0] == "persistence"
    assert loop._yara_category("C2_Cobalt_Strike_Beacon")[0] == "command_and_control"
    assert loop._yara_category("Unknown_Rule")[0] == "suspicious"


# ── Cross-source discrepancy detection (the tiebreaker moment) ──────────────
def test_correlation_flags_disk_only_process(log_dir):
    agent = loop.FindEvilAgent(
        case_dir="/tmp/CASE_TEST",
        disk_path="/mnt/case_disk",
        memory_path="/cases/CASE_TEST/memory.raw",
        verbose=False,
        max_iterations=3,
    )
    # cmd.exe ran on disk but is absent from memory.
    agent._disk_processes = {"cmd.exe", "explorer.exe"}
    agent._memory_processes = {"explorer.exe"}
    agent.phase_correlation()

    assert len(agent.result.discrepancies) == 1
    disc = agent.result.discrepancies[0]
    assert "cmd.exe" in disc.summary
    assert disc.resolved is True  # self-correction resolved it (memory present)
    assert len(disc.hypotheses) == 3


def test_correlation_no_false_discrepancy_when_consistent(log_dir):
    agent = loop.FindEvilAgent(
        case_dir="/tmp/CASE_TEST",
        disk_path="/mnt/case_disk",
        memory_path="/cases/CASE_TEST/memory.raw",
        verbose=False,
    )
    agent._disk_processes = {"explorer.exe"}
    agent._memory_processes = {"explorer.exe", "lsass.exe"}
    agent.phase_correlation()
    assert agent.result.discrepancies == []


def test_no_memory_means_no_discrepancy(log_dir):
    agent = loop.FindEvilAgent(
        case_dir="/tmp/CASE_TEST", disk_path="/mnt/case_disk", memory_path=None, verbose=False
    )
    agent._disk_processes = {"cmd.exe"}
    agent.phase_correlation()
    assert agent.result.discrepancies == []
