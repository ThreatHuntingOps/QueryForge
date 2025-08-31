# Detection of Reconnaissance via Suspicious PowerShell Commands

## Severity or Impact of the Detected Behavior
- **Risk Score:** 70
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PowerShell-Recon-Detection
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of PowerShell commands commonly used for system and network reconnaissance. Adversaries often leverage PowerShell to enumerate users, gather system configuration, list services, inspect drives, and query network information. The presence of these commands—especially when executed together or in close succession—may indicate pre-attack reconnaissance activity. Detected behaviors include:

- PowerShell or pwsh processes executing reconnaissance commands such as:
  - `WindowsIdentity.GetCurrent()`
  - `systeminfo`
  - `tasklist /svc`
  - `Get-Service`
  - `Get-PSDrive`
  - `arp -a`

These techniques are associated with adversaries gathering information about the system, users, services, and network prior to further attack phases.

---

## ATT&CK Mapping

| Tactic                | Technique   | Subtechnique | Technique Name                                 |
|-----------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery    | T1059.001   | —            | Command and Scripting Interpreter: PowerShell  |
| TA0007 - Discovery    | T1033       | —            | System Owner/User Discovery                    |
| TA0007 - Discovery    | T1082       | —            | System Information Discovery                   |
| TA0007 - Discovery    | T1007       | —            | System Service Discovery                       |
| TA0007 - Discovery    | T1016       | —            | System Network Configuration Discovery         |

---

## Hunt Query Logic

This query identifies suspicious PowerShell process launches by looking for:

- PowerShell or pwsh processes
- Command lines containing reconnaissance commands such as `WindowsIdentity.GetCurrent`, `systeminfo`, `tasklist /svc`, `Get-Service`, `Get-PSDrive`, or `arp -a`

These patterns are indicative of adversaries performing discovery and reconnaissance activities.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// title=Reconnaissance via Suspicious PowerShell Commands  
// description=Detects PowerShell execution of commands commonly used for reconnaissance, including WindowsIdentity.GetCurrent(), systeminfo, tasklist /svc, Get-Service, Get-PSDrive, and arp -a.  
// MITRE_ATT&CK_TTP_ID=T1059.001, T1033, T1082, T1007, T1016

#event_simpleName=ProcessRollup2  
| (FileName = /powershell\.exe|pwsh\.exe/i)  
  AND (
    CommandLine = "*WindowsIdentity.GetCurrent*" OR
    CommandLine = "*systeminfo*" OR
    CommandLine = "*tasklist /svc*" OR
    CommandLine = "*Get-Service*" OR
    CommandLine = "*Get-PSDrive*" OR
    CommandLine = "*arp -a*"
  ) 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PowerShell scripts.
- **Required Artifacts:** Process creation logs and command-line arguments.

---

## Considerations

- Review the command line and context for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or malicious.
- Investigate if multiple reconnaissance commands are executed together or in close succession.

---

## False Positives

False positives may occur if:

- IT staff or legitimate automation scripts use PowerShell for system inventory, troubleshooting, or monitoring.
- Security tools or monitoring agents execute similar reconnaissance commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the command line and process context for intent and legitimacy.
2. Review user activity and system logs for signs of unauthorized reconnaissance.
3. Correlate with other alerts or suspicious activity to determine if this is part of a larger attack chain.
4. Isolate affected endpoints if malicious reconnaissance is confirmed.
5. Block or monitor suspicious PowerShell reconnaissance activity.

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1033 – System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK: T1007 – System Service Discovery](https://attack.mitre.org/techniques/T1007/)
- [MITRE ATT&CK: T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [CISA AA25-203A: #StopRansomware: Interlock](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-23 | Initial Detection | Created hunt query to detect reconnaissance via suspicious PowerShell commands              |
