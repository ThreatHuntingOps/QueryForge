# Detection of Lateral Movement via CIM Sessions and Remote Execution - Correlation Rule

## Severity or Impact
- Risk Score Guidance: 95 (Multi-Phase), 90 (WMI Remote Exec), 85 (CIM Session), 70 (Staging Only)
- Severity: HIGH when two or more phases correlate within the window; MEDIUM for single-phase detections.

## Analytics Metadata
- ID: HuntQuery-Windows-CIM-WMI-Lateral-Movement-T1021
- Operating Systems: WindowsEndpoint, WindowsServer
- False Positive Rate: Medium
- Query Language: Falcon LogScale
- Platform: CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Analytics
Correlates behaviors indicative of credential-based lateral movement and remote execution via CIM/WMI using CrowdStrike Falcon telemetry (as seen in Yurei campaigns). Three phases are evaluated, and a normalized risk score is derived inline:

- Phase 1: PowerShell CIM session creation (New-CimSession, Get-CimSession, PSCredential, Invoke-CimMethod)
- Phase 2: WMI remote execution (wmiprvse.exe spawning child processes like cmd.exe, powershell.exe/pwsh.exe, mshta.exe, rundll32.exe, regsvr32.exe)
- Phase 3: Staging/related activity (NewExecutableWritten/NewScriptWritten under PowerShell context; optional DNS allowlisting for noise reduction)

Risk scoring:
- phase_count >= 2 -> 95 (Multi-Phase)
- Phase 2 only -> 90 (WMI Remote Exec)
- Phase 1 only -> 85 (CIM Session)
- Phase 3 only -> 70 (Staging Only)

---

## ATT&CK Mapping

| Tactic                   | Technique | Subtechnique | Technique Name                              |
|--------------------------|----------:|-------------:|---------------------------------------------|
| TA0008 - Lateral Movement| T1021     | .002         | Remote Services: SMB/Windows Admin Shares   |
| TA0002 - Execution       | T1047     | -            | Windows Management Instrumentation          |
| TA0002 - Execution       | T1059     | .001         | Command and Scripting Interpreter: PowerShell |

---

## Query Logic
- Uses selfJoinFilter on [aid, falcon_pid] to correlate events for a given process context.
- Derives conditional counts: _CIM (Phase 1), _WMI (Phase 2), _RPCSMB (Phase 3).
- Converts to phase flags and totals phase_count.
- Assigns risk_label and risk_score inline to match the Severity guidance.
- Applies exclusions for known service accounts and jump boxes.

---

## Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: Multi-Phase CIM/WMI Lateral Movement Correlation with Inline Risk Scoring
// Description: Correlates PowerShell CIM usage, wmiprvse child spawns, and staging, then assigns a risk label/score.
// MITRE ATT&CK: T1021.002, T1047, T1059.001

| #repo="base_sensor" event_platform="Win"
| #event_simpleName =~ in(values=["ProcessRollup2","DnsRequest","NewExecutableWritten","NewScriptWritten"])
| #event_simpleName match { ProcessRollup2 => falcon_pid := TargetProcessId; * => falcon_pid := ContextProcessId; }
| selfJoinFilter([aid, falcon_pid],
    where=[
    // Phase 1: PowerShell CIM cmdlets
    { #event_simpleName="ProcessRollup2"
    | (ImageFileName="powershell.exe" or ImageFileName="pwsh.exe")
    | CommandLine=/\b(New-CimSession|Get-CimSession|Invoke-CimMethod|PSCredential)\b/i
    },
    // Phase 2: wmiprvse.exe spawning LOLBIN/script runners
    { #event_simpleName="ProcessRollup2"
    | ParentImageFileName="wmiprvse.exe"
    | (ImageFileName="cmd.exe" or ImageFileName="powershell.exe" or ImageFileName="pwsh.exe" or ImageFileName="mshta.exe" or ImageFileName="rundll32.exe" or ImageFileName="regsvr32.exe")
    },
    // Phase 3a: New script/exe written under PowerShell context (staging)
    { #event_simpleName="NewExecutableWritten" | ContextBaseFileName="powershell.exe" | FileName!= "__PSScriptPolicy*.ps1" },
    { #event_simpleName="NewExecutableWritten" | ContextBaseFileName="pwsh.exe"    | FileName!= "__PSScriptPolicy*.ps1" },
    { #event_simpleName="NewScriptWritten"    | ContextBaseFileName="powershell.exe" | FileName!= "__PSScriptPolicy*.ps1" },
    { #event_simpleName="NewScriptWritten"    | ContextBaseFileName="pwsh.exe"    | FileName!= "__PSScriptPolicy*.ps1" },
    // Phase 3b: DNS requests (noise reduction via allowlist)
    { #event_simpleName="DnsRequest"
    | DomainName =~ !in(values=[
    "*.microsoft.com","*.azureedge.net","*.powershellgallery.com","*.windowsupdate.com",
    "dist.nuget.org","*.digicert.com","packages.chocolatey.org","flc-api.crowdstrike.com"
    ])
    }
    ],
    prefilter=true
)
| UserName!="DOMAIN\\SCCM_SVC"
| UserName!="DOMAIN\\MonitoringSVC"
| ComputerName!="ADMIN-JUMP-01"
| ComputerName!="SCCM-SERVER-01"
| groupBy([aid, ComputerName, UserName, falcon_pid],
    function=[
    { #event_simpleName="ProcessRollup2" (ImageFileName="powershell.exe" or ImageFileName="pwsh.exe") CommandLine=/\b(New-CimSession|Get-CimSession|Invoke-CimMethod|PSCredential)\b/i | _CIM := count(#event_simpleName) },
    { #event_simpleName="ProcessRollup2" ParentImageFileName="wmiprvse.exe" (ImageFileName="cmd.exe" or ImageFileName="powershell.exe" or ImageFileName="pwsh.exe" or ImageFileName="mshta.exe" or ImageFileName="rundll32.exe" or ImageFileName="regsvr32.exe") | _WMI := count(#event_simpleName) },
    { (#event_simpleName="NewExecutableWritten" and ContextBaseFileName="powershell.exe") or (#event_simpleName="NewExecutableWritten" and ContextBaseFileName="pwsh.exe") or (#event_simpleName="NewScriptWritten" and ContextBaseFileName="powershell.exe") or (#event_simpleName="NewScriptWritten" and ContextBaseFileName="pwsh.exe") | _RPCSMB := count(#event_simpleName) },
    collect([#event_simpleName, ImageFileName, ParentImageFileName, CommandLine, DomainName, TargetFileName])
    ],
    limit=max
)
// Derive phase flags and count
| _cim_flag := 0
| _wmi_flag := 0
| _rpc_flag := 0
| _CIM>0 | _cim_flag := 1
| _WMI>0 | _wmi_flag := 1
| _RPCSMB>0 | _rpc_flag := 1
| _phase_count := _cim_flag + _wmi_flag + _rpc_flag
// Inline risk scoring that matches Analytics section
| risk_label := "Staging Only"
| risk_score := 70
| _phase_count>=2 | risk_label := "Multi-Phase"
| _phase_count>=2 | risk_score := 95
| _phase_count=1 and _wmi_flag=1 | risk_label := "WMI Remote Exec"
| _phase_count=1 and _wmi_flag=1 | risk_score := 90
| _phase_count=1 and _cim_flag=1 | risk_label := "CIM Session"
| _phase_count=1 and _cim_flag=1 | risk_score := 85
| select([aid, ComputerName, UserName, falcon_pid, _CIM, _WMI, _RPCSMB, _phase_count, risk_label, risk_score])
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                                 | ATT&CK Data Source | Data Component      |
|--------------------|----------------------------------------------------------|--------------------|---------------------|
| CrowdStrike Falcon | base_sensor: ProcessRollup2, DnsRequest, NewExecutableWritten, NewScriptWritten | Process/Command | Process Creation/Execution |
| CrowdStrike Falcon | base_sensor                                            | Network            | DNS                 |

Field notes:
- Identity: aid, ComputerName; user: UserName
- Process: ImageFileName, ParentImageFileName, TargetProcessId
- Staging: ContextBaseFileName, FileName
- DNS: DomainName (with allowlist for noise reduction)

---

## Execution Requirements
- Required Permissions: Elevated privileges typically required for remote WMI/CIM execution.
- Required Artifacts: Process creation with command lines, PowerShell telemetry, file creation/write, optional DNS, and parent-child relationships.

---

## Considerations
- Expect Phase 1 then Phase 2 within minutes; staging may occur before or after.
- Look for one source host/account interacting with many remote targets.
- Validate legitimacy of accounts performing CIM sessions; analyze parent chains.
- Maintain exclusions for service accounts and jump servers.

---

## False Positives
- Legitimate IT administration via PowerShell remoting; SCCM/monitoring; patch/help-desk tools.

Mitigations: Inventory approved tools/accounts; exclude jump/management infra; align to change windows; baseline normal behavior.

---

## Recommended Response Actions
1. Verify legitimacy via ticket/window; if suspicious, contain the source host.
2. Enumerate remote targets touched via CIM/WMI; analyze PowerShell command lines and parentage.
3. Check for ransomware indicators (VSS deletion, event log tampering, Yurei artifacts).
4. Inspect remote hosts for new files, suspicious processes/services, and encryption signs.
5. Review SMB writes and PsExec/net use; assess credential compromise and rotate if needed.
6. Preserve evidence; expand hunt; escalate to IR as required.

---

## References
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft Docs: CIM Cmdlets](https://learn.microsoft.com/powershell/module/cimcmdlets/)
- [Microsoft Docs: Windows Management Instrumentation](https://learn.microsoft.com/windows/win32/wmisdk/wmi-start-page)
- [Microsoft Docs: PSCredential Class](https://learn.microsoft.com/dotnet/api/system.management.automation.pscredential)

---

## Version History

| Version | Date       | Impact             | Notes                                                              |
|---------|------------|--------------------|--------------------------------------------------------------------|
| 1.1     | 2025-10-15 | Alignment          | Inline risk scoring; Analytics/Syntax sections aligned             |
| 1.0     | 2025-10-12 | Initial Detection  | Correlation rule for CIM/WMI lateral movement (Yurei context)      |
