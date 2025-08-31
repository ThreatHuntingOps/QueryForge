# Detection of Suspicious AnyDesk Installation and Persistence via PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnyDesk-PowerShell-Persistence
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects potentially malicious installation and persistence of AnyDesk through PowerShell automation (e.g., any.ps1). The query tracks web-based downloading of AnyDesk.exe, stealth installation into ProgramData, and command-line password setup, which may indicate unauthorized remote access setup by threat actors. It also identifies suspicious process chains (PowerShell ➝ cmd.exe ➝ anydesk.exe) and hardcoded password usage, as observed in recent ransomware affiliate campaigns.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                              |
|------------------------------|-------------|--------------|-------------------------------------------------------------|
| TA0003 - Persistence         | T1547.010   | —            | Persistence via Windows Service                             |
| TA0002 - Execution           | T1059.001   | —            | PowerShell Execution                                        |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                                       |
| TA0008 - Lateral Movement    | T1569.002   | —            | Service Execution                                           |
| TA0002 - Execution           | T1219       | —            | Remote Access Software                                      |

---

## Hunt Query Logic

This query identifies:

- PowerShell scripts using System.Net.WebClient to download AnyDesk from the web
- File creation of AnyDesk.exe in ProgramData (a common persistence location)
- Silent installation and persistence flags (`--install`, `--start-with-win`, `--silent`)
- Command-line password setup (`--set-password Admin#123`)
- Suspicious process chains: PowerShell ➝ cmd.exe ➝ anydesk.exe

These behaviors are rarely seen in legitimate administrative activity and are strong indicators of unauthorized remote access setup and persistence.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 OR #event_simpleName=FileCreate OR #event_simpleName=ScriptLoad // PowerShell downloading AnyDesk  
| (ParentBaseFileName="powershell.exe" AND CommandLine="*System.Net.WebClient*.DownloadFile*" AND CommandLine="*anydesk*") // File creation in ProgramData  
| (#event_simpleName=FileCreate AND FilePath="*\ProgramData\AnyDesk.exe") // AnyDesk silent install and persistence  
| (FileName="anydesk.exe" AND CommandLine="*--install*" AND CommandLine="*--start-with-win*" AND CommandLine="*--silent*") // Setting hardcoded password  
| (CommandLine="*--set-password*" AND CommandLine="*Admin#123*") // Process chain: PowerShell ➝ cmd.exe ➝ anydesk.exe  
| ((ParentBaseFileName="powershell.exe" AND FileName="cmd.exe") OR (ParentBaseFileName="cmd.exe" AND FileName="anydesk.exe"))  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |
| Falcon       | N/A      | FileCreate       | File                | File Creation          |
| Falcon       | N/A      | ScriptLoad       | Script              | Script Load            |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PowerShell scripts, download files, and install software.
- **Required Artifacts:** Script execution logs, process creation events, file creation logs, and command-line arguments.

---

## Considerations

- Investigate the source and contents of PowerShell scripts and AnyDesk binaries.
- Review the context of AnyDesk installation, including parent process and user account.
- Correlate with network logs for suspicious downloads or remote access attempts.
- Examine for follow-on activity such as lateral movement or privilege escalation.

---

## False Positives

False positives may occur if:

- Administrators are legitimately automating AnyDesk deployment for IT support.
- Security or compliance tools use similar automation for remote access management.

---

## Recommended Response Actions

1. Investigate the initiating PowerShell script and its source.
2. Analyze command-line arguments and installation paths for malicious indicators.
3. Review network and process logs for unauthorized remote access or persistence.
4. Isolate affected systems if confirmed malicious.
5. Reset AnyDesk credentials and review access policies.

---

## References

- [MITRE ATT&CK: T1547.010 – Persistence via Windows Service](https://attack.mitre.org/techniques/T1547/010/)
- [MITRE ATT&CK: T1059.001 – PowerShell Execution](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1569.002 – Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-30 | Initial Detection | Created hunt query to detect suspicious AnyDesk installation and persistence via PowerShell |
