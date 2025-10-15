# Detection of Lateral Movement via CIM Sessions and Remote Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (Multi-Phase), 90 (WMI Remote Exec), 85 (CIM Session), 70 (WMI Network)
- **Severity:** HIGH to MEDIUM (based on detection phase)

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-CIM-WMI-Lateral-Movement-T1021
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Hunt Analytics

This hunt detects PowerShell commands establishing CIM sessions and remote execution behaviors leveraging WMI, using CrowdStrike Falcon telemetry. Yurei may spread laterally by creating PSCredential objects, establishing CIM sessions, copying payloads, and remotely executing them. This query highlights indicators across three phases:

- **Phase 1:** PowerShell CIM session creation/usage (New-CimSession, Get-CimSession, PSCredential, Invoke-CimMethod)
- **Phase 2:** WMI remote execution (wmiprvse.exe spawning cmd.exe, powershell.exe/pwsh.exe, mshta.exe, rundll32.exe, regsvr32.exe)
- **Phase 3:** Network connections to RPC/SMB ports (135, 445)

---

## ATT&CK Mapping

| Tactic                   | Technique | Subtechnique | Technique Name                                   |
|--------------------------|----------:|-------------:|--------------------------------------------------|
| TA0008 - Lateral Movement| T1021     | .002         | Remote Services: SMB/Windows Admin Shares        |
| TA0002 - Execution       | T1047     | -            | Windows Management Instrumentation               |
| TA0002 - Execution       | T1059.001 | -            | Command and Scripting Interpreter: PowerShell    |

---

## Hunt Query Logic

Multi-phase approach:
- Phase 1: PowerShell CIM cmdlets usage
- Phase 2: wmiprvse.exe spawning suspicious children
- Phase 3: RPC/SMB network activity with remote address

Tuning: Exclude known management service accounts (SCCM, monitoring) and jump hosts.

---

## Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: CIM/WMI-Based Remote Execution for Lateral Movement (Strict, No Assignments)
// Description: Detects PowerShell CIM session usage, wmiprvse.exe child spawns, or network activity on ports 135/445.
// MITRE ATT&CK: T1021.002, T1047, T1059.001

#event_simpleName=*
| event_platform="Win"

// Phase filters combined with OR:
// - Phase 1: PowerShell CIM session creation/usage
// - Phase 2: wmiprvse.exe spawning suspicious children
// - Phase 3: Network activity on RPC/SMB ports with remote address present
|
  (
    (
    (ImageFileName="powershell.exe" or ImageFileName="pwsh.exe")
    and (
    CommandLine = "New-CimSession"
    or CommandLine="Get-CimSession"
    or CommandLine="Invoke-CimMethod"
    or CommandLine="PSCredential"
    )
    )
    or
    (
    ParentImageFileName="wmiprvse.exe"
    and (
    ImageFileName="cmd.exe"
    or ImageFileName="powershell.exe"
    or ImageFileName="pwsh.exe"
    or ImageFileName="mshta.exe"
    or ImageFileName="rundll32.exe"
    or ImageFileName="regsvr32.exe"
    )
    )
    or
    (
    (
    TargetPort=135 or TargetPort=445
    or RemotePort=135 or RemotePort=445
    or action_remote_port=135 or action_remote_port=445
    or dst_action_external_port=135 or dst_action_external_port=445
    )
    and (
    RemoteAddress != null
    or action_remote_ip != null
    or DstIpAddr != null
    )
    )
  )

// Exclusions: known legitimate service accounts and admin hosts
| UserName != "DOMAIN\\SCCM_SVC"
| UserName != "DOMAIN\\MonitoringSVC"
| ComputerName != "ADMIN-JUMP-01"
| ComputerName != "SCCM-SERVER-01"

// Output
| select(
    @timestamp,
    aid,
    ComputerName,
    UserName,
    ImageFileName,
    CommandLine,
    ParentImageFileName,
    ParentCommandLine,
    RemoteAddress,
    RemotePort,
    RemoteIP,
    DstIpAddr,
    TargetPort,
    #event_simpleName
)
| sort(field=@timestamp, order=desc, limit=1000)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                              | ATT&CK Data Source | Data Component         |
|--------------------|-------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon | base_sensor: ProcessRollup2 (process/command lines)   | Process/Command    | Process Creation/Exec  |
| CrowdStrike Falcon | base_sensor: NetworkConnect* (if present)             | Network            | Network Connection     |

Field notes:
- Identity: aid, ComputerName; user: UserName
- Process fields: ImageFileName, ParentImageFileName; CommandLine for cmdlet detection
- Network fields vary: RemotePort/TargetPort/action_remote_port/dst_action_external_port, RemoteAddress/action_remote_ip/DstIpAddr

---

## Execution Requirements
- **Required Permissions:** Elevated privileges typically required for remote WMI/CIM execution.
- **Required Artifacts:** Process creation telemetry with command-line arguments; network connection visibility; WMI activity logs when available.

---

## Considerations
- Time-correlate CIM session creation followed by wmiprvse.exe child processes within minutes.
- Look for bursts of remote activity against multiple hosts from a single source.
- Validate service accounts/jump hosts and tune exclusions accordingly.
- Correlate with remote file creation on destination hosts.

---

## False Positives
- Legitimate use by IT admins, SCCM, monitoring, or patch systems.
- Helpdesk remote assistance leveraging WMI.

Mitigation: Maintain inventories of approved tools/accounts; add targeted exclusions; compare against change windows.

---

## Recommended Response Actions
1. Triage authorization; if suspicious, contain the source host (Falcon Host containment).
2. Enumerate destination hosts targeted; scope lateral spread.
3. Review full PowerShell command lines and parent process lineage.
4. Correlate with Yurei indicators (VSS deletion, log wipes, `.Yurei` files, `_README_Yurei.txt`, temp staging).
5. Inspect destination hosts for file drops, suspicious processes, service creation, or encryption.
6. Review network telemetry for parallel lateral movement (SMB writes, PsExec, net use).
7. Investigate credential use; rotate/disable affected accounts.
8. Preserve forensic artifacts (memory, process lists) on source and destination.
9. Expand hunt for similar patterns; consider Falcon OverWatch escalation.

---

## References
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft: CIM Cmdlets](https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/)
- [Microsoft: Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)
- [Microsoft: PSCredential Class](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential)

---

## Version History

| Version | Date       | Impact             | Notes                                                             |
|---------|------------|--------------------|-------------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Detection  | Hunt query for CIM/WMI-based lateral movement (Yurei context)     |
