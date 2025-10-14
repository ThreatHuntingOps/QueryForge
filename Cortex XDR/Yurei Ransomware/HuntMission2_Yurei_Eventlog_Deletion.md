# Detection of Windows Event Log Deletion via PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** HIGH

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PowerShell-EventLog-Deletion-T1070
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects PowerShell commands that recursively delete Windows event log files or use built-in cmdlets to clear logs. Yurei ransomware systematically wipes event logs to cover its tracks. This behavior is almost never legitimate outside of controlled testing environments and is a strong indicator of adversary activity. Detected behaviors include:

- Recursive deletion of event log files from `winevt\Logs` or `System32\Logs`
- PowerShell cmdlets for log clearing (`Clear-EventLog`, `Limit-EventLog`)
- Use of `wevtutil` to clear event logs via PowerShell
- Combination of `Get-ChildItem` and `Remove-Item` targeting log directories

These techniques are associated with anti-forensics operations designed to hinder incident response and forensic investigation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1070       | .001         | Indicator Removal: Clear Windows Event Logs   |
| TA0002 - Execution           | T1059       | .001         | Command and Scripting Interpreter: PowerShell |

---

## Hunt Query Logic

This query identifies suspicious PowerShell activity by looking for:

- Process names matching `powershell.exe` or `powershell`
- Command lines containing event log deletion patterns:
  - `Remove-Item` + `winevt\Logs`
  - `Remove-Item` + `System32\Logs`
  - `Get-ChildItem` + `Remove-Item` + `Logs`
  - `Clear-EventLog` cmdlet
  - `Limit-EventLog` cmdlet
  - `wevtutil` + `cl` (clear)
  - `wevtutil` + `clear-log`
- Exclusions for SYSTEM account executions (adjust based on environment)

These patterns are highly indicative of anti-forensics activity attempting to erase evidence before or after malicious operations.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM

```xql
// Title: PowerShell Event Log Deletion and Anti-Forensics
// Description: Detects PowerShell commands that recursively delete Windows event log files or use built-in cmdlets to clear logs. Yurei ransomware systematically wipes event logs to cover its tracks.
// MITRE ATT&CK TTP ID: T1070.001, T1059.001

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
        and actor_process_image_name contains "powershell"
        and (
            // Recursive deletion of event log files
            (actor_process_command_line contains "Remove-Item" and actor_process_command_line contains "winevt\Logs")
            or (actor_process_command_line contains "Remove-Item" and actor_process_command_line contains "System32\Logs")
            or (actor_process_command_line contains "Get-ChildItem" and actor_process_command_line contains "Remove-Item" and actor_process_command_line contains "Logs")

            // PowerShell cmdlet-based log clearing
            or actor_process_command_line contains "Clear-EventLog"
            or actor_process_command_line contains "Limit-EventLog"
            or (actor_process_command_line contains "wevtutil" and actor_process_command_line contains "cl")
            or (actor_process_command_line contains "wevtutil" and actor_process_command_line contains "clear-log")
        )

// Exclude legitimate log management in maintenance windows (customize time range)
| filter actor_effective_username not in ("SYSTEM")  // Adjust based on environment

// Enrichment
| alter severity = "HIGH",
        detection_category = "Anti-Forensics - Event Log Deletion",
        risk_score = 95,
        mitre_technique = "T1070.001, T1059.001"

| fields _time,
         agent_hostname,
         actor_process_image_name,
         actor_process_command_line,
         actor_effective_username,
         causality_actor_process_image_name,
         severity,
         detection_category,
         risk_score

| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |
| Cortex       | xdr_data         | Command             | Command Execution      |

---

## Execution Requirements

- **Required Permissions:** Administrator or elevated privileges to delete or clear event logs.
- **Required Artifacts:** Process creation logs with command-line arguments, PowerShell execution logs, event log modification records.

---

## Considerations

- Review the user account executing the command for legitimacy and authorization.
- Correlate with other ransomware indicators such as VSS deletion, file encryption, or lateral movement.
- Investigate the parent process (`causality_actor_process_image_name`) to determine the execution chain.
- Check for additional anti-forensics behaviors such as timestamp manipulation, secure deletion, or memory wiping.
- Validate if the activity aligns with scheduled maintenance or authorized security testing.
- Consider temporal analysis: Event log deletion immediately following suspicious activity is highly indicative of malicious intent.

---

## False Positives

False positives may occur if:

- IT administrators manually clear event logs during system maintenance or troubleshooting.
- Automated scripts or scheduled tasks perform log rotation or cleanup operations.
- Security testing or penetration testing activities include log clearing as part of authorized exercises.
- Log management tools perform automated cleanup based on retention policies.

**Mitigation:** Tune exclusions based on authorized administrative accounts, maintenance windows, and known legitimate log management tools.

---

## Recommended Response Actions

1. **Immediate Investigation:** Prioritize investigation of the affected endpoint and user account.
2. **Isolate Endpoint:** If malicious activity is suspected, isolate the affected endpoint from the network.
3. **Analyze Command Context:** Review the full command line, parent process, and user account for signs of compromise.
4. **Correlate with Ransomware Indicators:** Search for additional Yurei ransomware artifacts:
   - VSS/backup deletion commands
   - Files with `.Yurei` extension
   - `_README_Yurei.txt` ransom notes
   - Payload staging in `%LOCALAPPDATA%\Temp`
   - Suspicious executables (`WindowsUpdate.exe`, `svchost.exe`, `System32_Backup.exe`)
5. **Check for Lateral Movement:** Investigate CIM sessions, PSCredential usage, `net use` commands, and SMB write activity.
6. **Preserve Forensic Evidence:** Immediately collect volatile artifacts (memory dumps, process listings) before further investigation.
7. **Review Backup Event Logs:** Check if event logs were backed up to a SIEM or centralized logging system before deletion.
8. **Credential Rotation:** Rotate credentials for affected accounts and disable compromised accounts.
9. **Threat Hunt:** Conduct a broader hunt across the environment for similar behaviors and IOCs.
10. **Engage Incident Response:** Escalate to IR team for full investigation and containment.

---

## References

- [MITRE ATT&CK: T1070.001 – Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft: Windows Event Logs](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging)
- [Microsoft: Clear-EventLog Cmdlet](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/clear-eventlog)
- [Microsoft: wevtutil Command-Line Tool](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-10 | Initial Detection | Created hunt query to detect PowerShell-based event log deletion for Yurei ransomware     |

