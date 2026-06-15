/*
 * Find Evil! — Custom YARA Rules Library
 * Covers: APT tooling, lateral movement, persistence, C2 patterns
 * Sources: Community rules adapted for Windows forensic disk/memory analysis
 * License: Apache 2.0
 *
 * Usage in scan_yara():
 *   rules_path = "/opt/find-evil/yara_rules/find_evil_custom.yar"
 *   + community rules from /opt/find-evil/yara_rules/community/
 */

import "pe"
import "math"

/* ══════════════════════════════════════════════════════════════════════════
   CATEGORY 1: LATERAL MOVEMENT TOOLS
   ══════════════════════════════════════════════════════════════════════════ */

rule LateralMovement_PsExec_Artifacts
{
    meta:
        description = "Detects PsExec artifacts on disk — lateral movement indicator"
        author = "Find Evil!"
        severity = "HIGH"
        category = "lateral_movement"
        mitre_attack = "T1021.002 — SMB/Windows Admin Shares"

    strings:
        $psexec_svc  = "PSEXESVC" ascii wide nocase
        $psexec_pipe = "\\\\.\\pipe\\PSEXESVC" ascii wide nocase
        $psexec_str1 = "PsExec" ascii wide
        $psexec_str2 = "Sysinternals" ascii wide
        $psexec_str3 = "psexec.exe" ascii wide nocase

    condition:
        2 of them
}

rule LateralMovement_WMI_Persistence
{
    meta:
        description = "WMI event subscription used for persistence/lateral movement"
        severity = "HIGH"
        category = "persistence"
        mitre_attack = "T1546.003 — WMI Event Subscription"

    strings:
        $wmi1 = "ActiveScriptEventConsumer" ascii wide nocase
        $wmi2 = "CommandLineEventConsumer" ascii wide nocase
        $wmi3 = "__EventFilter" ascii wide
        $wmi4 = "__FilterToConsumerBinding" ascii wide
        $wmi5 = "scrcons.exe" ascii wide nocase

    condition:
        any of ($wmi1, $wmi2) and any of ($wmi3, $wmi4)
}

rule LateralMovement_Pass_The_Hash
{
    meta:
        description = "Pass-the-hash / pass-the-ticket indicators in memory"
        severity = "HIGH"
        category = "credential_access"
        mitre_attack = "T1550.002 — Pass the Hash"

    strings:
        $sekurlsa  = "sekurlsa" ascii wide nocase
        $mimikatz1 = "mimikatz" ascii wide nocase
        $mimikatz2 = "mimilib" ascii wide nocase
        $mimikatz3 = "mimidrv" ascii wide nocase
        $lsadump   = "lsadump" ascii wide nocase
        $wdigest   = "wdigest" ascii wide nocase
        $kerberos  = "kerberoast" ascii wide nocase

    condition:
        any of them
}

/* ══════════════════════════════════════════════════════════════════════════
   CATEGORY 2: PERSISTENCE MECHANISMS
   ══════════════════════════════════════════════════════════════════════════ */

rule Persistence_Registry_Run_Keys_Suspicious
{
    meta:
        description = "Suspicious executable in registry Run key location"
        severity = "MEDIUM"
        category = "persistence"
        mitre_attack = "T1547.001 — Registry Run Keys / Startup Folder"

    strings:
        $run_key1 = "\\CurrentVersion\\Run\\" ascii wide nocase
        $run_key2 = "\\CurrentVersion\\RunOnce\\" ascii wide nocase
        $run_key3 = "\\CurrentVersion\\RunServices\\" ascii wide nocase
        $suspicious_ext1 = ".ps1" ascii wide nocase
        $suspicious_ext2 = ".vbs" ascii wide nocase
        $suspicious_ext3 = ".bat" ascii wide nocase
        $suspicious_ext4 = "powershell" ascii wide nocase
        $suspicious_ext5 = "cmd /c" ascii wide nocase
        $suspicious_ext6 = "wscript" ascii wide nocase

    condition:
        any of ($run_key*) and any of ($suspicious_ext*)
}

rule Persistence_Scheduled_Task_Suspicious
{
    meta:
        description = "Scheduled task with suspicious execution pattern"
        severity = "MEDIUM"
        category = "persistence"
        mitre_attack = "T1053.005 — Scheduled Task"

    strings:
        $task1 = "<Task " ascii wide
        $task2 = "schtasks.exe" ascii wide nocase
        $lolbin1 = "powershell.exe -enc" ascii wide nocase
        $lolbin2 = "powershell.exe -e " ascii wide nocase
        $lolbin3 = "certutil" ascii wide nocase
        $lolbin4 = "regsvr32" ascii wide nocase
        $lolbin5 = "mshta" ascii wide nocase
        $lolbin6 = "bitsadmin" ascii wide nocase
        $lolbin7 = "wmic" ascii wide nocase

    condition:
        any of ($task*) and any of ($lolbin*)
}

rule Persistence_DLL_Hijacking
{
    meta:
        description = "DLL placed in location indicating hijacking attempt"
        severity = "HIGH"
        category = "persistence"
        mitre_attack = "T1574.001 — DLL Search Order Hijacking"

    strings:
        $sys32   = "C:\\Windows\\System32\\" ascii wide nocase
        $syswow  = "C:\\Windows\\SysWOW64\\" ascii wide nocase
        $dll_str = ".dll" ascii wide nocase

    condition:
        pe.is_dll() and
        not pe.is_signed() and
        (any of ($sys32, $syswow))
}

/* ══════════════════════════════════════════════════════════════════════════
   CATEGORY 3: DEFENSE EVASION
   ══════════════════════════════════════════════════════════════════════════ */

rule Evasion_Timestomping_Indicator
{
    meta:
        description = "File with suspicious timestamp pattern — possible timestomping"
        severity = "MEDIUM"
        category = "defense_evasion"
        mitre_attack = "T1070.006 — Timestomp"
        note = "Requires correlation with $STANDARD_INFORMATION vs $FILE_NAME timestamps"

    strings:
        $setfiletime = "SetFileTime" ascii wide
        $ntsetinfo   = "NtSetInformationFile" ascii wide
        $touch_cmd   = "touch -t" ascii wide nocase
        $mace        = "ModifyAccessCreate" ascii wide nocase

    condition:
        any of them
}

rule Evasion_Process_Injection
{
    meta:
        description = "Process injection API pattern — memory injection indicator"
        severity = "HIGH"
        category = "defense_evasion"
        mitre_attack = "T1055 — Process Injection"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide
        $api5 = "RtlCreateUserThread" ascii wide
        $api6 = "QueueUserAPC" ascii wide
        $api7 = "SetWindowsHookEx" ascii wide

    condition:
        3 of them
}

rule Evasion_AMSI_Bypass
{
    meta:
        description = "AMSI bypass technique — antimalware scan interface evasion"
        severity = "HIGH"
        category = "defense_evasion"
        mitre_attack = "T1562.001 — Disable or Modify Tools"

    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide nocase
        $amsi2 = "amsi.dll" ascii wide nocase
        $amsi3 = "AmsiInitialize" ascii wide nocase
        $patch1 = { 31 C0 C3 }          // xor eax, eax; ret (common patch)
        $patch2 = { B8 57 00 07 80 C3 }  // mov eax, 0x80070057; ret

    condition:
        any of ($amsi*) and any of ($patch*)
}

rule Evasion_PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell encoded command — common obfuscation technique"
        severity = "MEDIUM"
        category = "defense_evasion"
        mitre_attack = "T1059.001 — PowerShell"

    strings:
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-EncodedCommand" ascii wide nocase
        $enc3 = "-e " ascii wide nocase
        $ps1  = "powershell" ascii wide nocase
        $ps2  = "pwsh" ascii wide nocase

    condition:
        any of ($ps*) and any of ($enc*)
}

/* ══════════════════════════════════════════════════════════════════════════
   CATEGORY 4: COMMAND AND CONTROL
   ══════════════════════════════════════════════════════════════════════════ */

rule C2_Cobalt_Strike_Beacon
{
    meta:
        description = "Cobalt Strike beacon artifacts"
        severity = "CRITICAL"
        category = "c2"
        mitre_attack = "T1071 — Application Layer Protocol"

    strings:
        $cs1 = "beacon" ascii wide nocase
        $cs2 = "cobaltstrike" ascii wide nocase
        $cs3 = "%08x-%04x-%04x-%04x-" ascii  // UUID format in CS comms
        $cs4 = "ReflectiveDllInjection" ascii wide
        $cs5 = { FC 48 83 E4 F0 E8 }   // Common CS shellcode prologue

    condition:
        any of them
}

rule C2_Reverse_Shell_Pattern
{
    meta:
        description = "Reverse shell connection pattern in memory or artifacts"
        severity = "HIGH"
        category = "c2"
        mitre_attack = "T1059 — Command and Scripting Interpreter"

    strings:
        $nc1  = "nc -e /bin/bash" ascii wide nocase
        $nc2  = "nc -e cmd.exe" ascii wide nocase
        $bash1 = "bash -i >& /dev/tcp/" ascii wide nocase
        $ps1  = "New-Object Net.Sockets.TCPClient" ascii wide nocase
        $ps2  = "System.Net.Sockets.TcpClient" ascii wide nocase

    condition:
        any of them
}

rule C2_Suspicious_Outbound_Port
{
    meta:
        description = "Connection attempt to common C2 ports"
        severity = "MEDIUM"
        category = "c2"
        note = "Correlate with volatility netscan output"

    strings:
        $port4444 = ":4444" ascii wide
        $port1337 = ":1337" ascii wide
        $port31337 = ":31337" ascii wide
        $port8443  = ":8443" ascii wide

    condition:
        any of them
}

/* ══════════════════════════════════════════════════════════════════════════
   CATEGORY 5: DATA EXFILTRATION
   ══════════════════════════════════════════════════════════════════════════ */

rule Exfiltration_Archive_Staging
{
    meta:
        description = "Data archiving tools used for staging — common pre-exfiltration"
        severity = "MEDIUM"
        category = "exfiltration"
        mitre_attack = "T1560 — Archive Collected Data"

    strings:
        $7zip1  = "7z.exe" ascii wide nocase
        $7zip2  = "7za.exe" ascii wide nocase
        $rar1   = "rar.exe" ascii wide nocase
        $rar2   = "winrar" ascii wide nocase
        $arg_pw = " -p" ascii wide  // Password-protected archive arg

    condition:
        any of ($7zip*, $rar*) and $arg_pw
}

rule Exfiltration_Credential_Harvesting
{
    meta:
        description = "Credential file access pattern — LSASS dump or SAM access"
        severity = "CRITICAL"
        category = "credential_access"
        mitre_attack = "T1003 — OS Credential Dumping"

    strings:
        $lsass  = "lsass.exe" ascii wide nocase
        $sam    = "\\Windows\\System32\\config\\SAM" ascii wide nocase
        $system = "\\Windows\\System32\\config\\SYSTEM" ascii wide nocase
        $ntds   = "ntds.dit" ascii wide nocase
        $procdump = "procdump" ascii wide nocase
        $comsvcs = "comsvcs.dll" ascii wide nocase

    condition:
        any of them
}

/* ══════════════════════════════════════════════════════════════════════════
   CATEGORY 6: SUSPICIOUS BINARIES
   ══════════════════════════════════════════════════════════════════════════ */

rule Suspicious_PE_Unsigned_System32
{
    meta:
        description = "Unsigned PE in System32 — possible DLL sideloading"
        severity = "HIGH"
        category = "masquerading"
        mitre_attack = "T1036 — Masquerading"

    condition:
        pe.is_pe() and
        not pe.is_signed() and
        pe.number_of_sections < 3 and
        (uint32(pe.entry_point) == 0 or pe.entry_point == 0)
}

rule Suspicious_High_Entropy_Section
{
    meta:
        description = "PE section with very high entropy — possible packing or encryption"
        severity = "MEDIUM"
        category = "obfuscation"
        note = "High entropy in code sections often indicates packed/encrypted payloads"

    condition:
        pe.is_pe() and
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0 and
            section.raw_data_size > 4096
        )
}

rule Suspicious_LOLBIN_Execution
{
    meta:
        description = "Living-off-the-land binary execution with suspicious arguments"
        severity = "MEDIUM"
        category = "execution"
        mitre_attack = "T1218 — System Binary Proxy Execution"

    strings:
        $regsvr = "regsvr32.exe /s /n /u /i:http" ascii wide nocase
        $mshta1 = "mshta.exe http" ascii wide nocase
        $mshta2 = "mshta.exe vbscript" ascii wide nocase
        $rundll1 = "rundll32.exe javascript" ascii wide nocase
        $certutil = "certutil.exe -decode" ascii wide nocase
        $certutil2 = "certutil.exe -urlcache" ascii wide nocase
        $wmic_xsl = "wmic.exe ...xsl" ascii wide nocase

    condition:
        any of them
}

/* ══════════════════════════════════════════════════════════════════════════
   CATEGORY 7: APT-SPECIFIC INDICATORS
   ══════════════════════════════════════════════════════════════════════════ */

rule APT_GTG1002_Indicators
{
    meta:
        description = "GTG-1002 (Chinese state-sponsored) — AI-assisted attack indicators"
        author = "Find Evil! — based on Anthropic Nov 2025 disclosure"
        severity = "CRITICAL"
        category = "apt"
        reference = "Anthropic GTG-1002 Threat Intelligence Report, Nov 2025"

    strings:
        $mcp_agent  = "model_context_protocol" ascii wide nocase
        $claude_code = "claude_code" ascii wide nocase
        $recon1     = "reconnaissance.py" ascii wide nocase
        $recon2     = "autonomous_recon" ascii wide nocase
        $lateral1   = "lateral_movement.py" ascii wide nocase
        $ai_persist = "ai_agent_persist" ascii wide nocase

    condition:
        any of them
}

rule APT_Tool_Impacket
{
    meta:
        description = "Impacket toolkit artifacts — used by multiple APT groups for lateral movement"
        severity = "HIGH"
        category = "apt_tooling"
        mitre_attack = "T1021 — Remote Services"

    strings:
        $impacket1 = "impacket" ascii wide nocase
        $impacket2 = "secretsdump" ascii wide nocase
        $impacket3 = "wmiexec" ascii wide nocase
        $impacket4 = "smbexec" ascii wide nocase
        $impacket5 = "psexec.py" ascii wide nocase
        $impacket6 = "dcomexec" ascii wide nocase

    condition:
        any of them
}
