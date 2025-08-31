# Detection of PowerShell Used for VM Shutdown and Shadow Copy Deletion

## Severity or Impact of the Detected Behavior

- **Risk Score:** 85  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-PowerShell-VMShadowCopy
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious executions of `powershell.exe` where the command line includes actions to force shutdown virtual machines and remove volume shadow copies. These behaviors are commonly observed in ransomware operations to maximize impact and inhibit recovery, as attackers attempt to disable backup mechanisms and disrupt business continuity.

Detected behaviors include:

- Use of PowerShell to enumerate or stop virtual machines (e.g., `Get-VM`, `Stop-VM`)
- Removal of shadow copies via WMI or CIM (e.g., `Win32_ShadowCopy`, `Remove-CimInstance`)
- Attempts to inhibit system recovery and facilitate ransomware deployment

Such techniques are strongly associated with ransomware groups, including those documented in recent threat intelligence such as the [RansomHub deployment via RDP password spray](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/).

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution            | T1059.001   | —            | Command and Scripting Interpreter: PowerShell |
| TA0040 - Impact               | T1490       | —            | Inhibit System Recovery                       |
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact                     |

---

## Hunt Query Logic

This query identifies suspicious `powershell.exe` executions that match the following indicators:

- Command lines containing VM management or shadow copy deletion commands
- Use of PowerShell to interact with virtualization and backup infrastructure
- Patterns consistent with ransomware pre-encryption activity

These patterns are often seen in ransomware campaigns aiming to maximize damage and prevent recovery.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    

| (FileName = "powershell.exe")    

| (CommandLine = "*Get-VM*" OR CommandLine = "*Stop-VM*" OR CommandLine = "*Win32_ShadowCopy*" OR CommandLine = "*Remove-CimInstance*") 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to run PowerShell and manage VMs or shadow copies.
- **Required Artifacts:** Process creation logs, command-line arguments, PowerShell logs.

---

## Considerations

- Investigate the context of PowerShell usage—are these administrative actions or unexpected?
- Validate if the account running the commands is authorized for VM or backup management.
- Review for additional signs of ransomware activity, such as suspicious file encryption or lateral movement.
- Correlate with threat intelligence on recent ransomware campaigns (e.g., [RansomHub](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)).

---

## False Positives

False positives may occur if:

- Legitimate administrators are performing VM maintenance or backup management via PowerShell.
- Scheduled tasks or automation scripts use similar commands for valid operational reasons.

---

## Recommended Response Actions

1. Investigate the user and host context of the detected PowerShell command.
2. Review recent authentication and privilege escalation events.
3. Check for additional indicators of ransomware, such as file encryption or ransom notes.
4. Isolate affected systems if malicious activity is confirmed.
5. Restore from known-good backups if data loss or encryption is detected.

---

## References

- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-09 | Initial Detection | Created hunt query to detect PowerShell-based VM shutdown and shadow copy deletion behavior |
