# Detection of Exfiltration of Sensitive File Types via Rclone

## Severity or Impact of the Detected Behavior

- **Risk Score:** 95  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Rclone-Filetype-Exfil
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the execution of Rclone or its associated scripts (such as `rcl.bat`) with command lines referencing sensitive file types, including `.doc`, `.pdf`, `.xls`, `.pst`, and `.mbox`. These file types are commonly targeted for exfiltration by threat actors due to their potential to contain confidential documents, emails, and business data. The presence of these patterns in process creation logs is a strong indicator of automated data theft or exfiltration activity.

Detected behaviors include:

- Execution of `rclone.exe` or `rcl.bat` with command lines referencing sensitive file types
- Attempts to automate the exfiltration of documents, spreadsheets, emails, and archives
- Commonly observed in ransomware, APT, and data theft campaigns

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0010 - Exfiltration         | T1020       | —            | Automated Exfiltration                        |
| TA0010 - Exfiltration         | T1041       | —            | Exfiltration Over C2 Channel                  |

---

## Hunt Query Logic

This query identifies suspicious process creation events for `rclone.exe` or `rcl.bat` where the command line references sensitive file types. Such activity is rarely seen in legitimate environments and should be investigated, especially if observed alongside large outbound data transfers.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    

| (FileName = /rclone\.exe/i OR FileName = /rcl\.bat/i)    

| (CommandLine = "*.doc*" OR CommandLine = "*.pdf*" OR CommandLine = "*.xls*" OR CommandLine = "*.pst*" OR CommandLine = "*.mbox*")  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to execute binaries and scripts.
- **Required Artifacts:** Process creation logs, command-line arguments, network connection logs.

---

## Considerations

- Investigate the user account and host context for the detected tool or script execution.
- Review for additional signs of data exfiltration, such as large outbound transfers or connections to cloud storage/SFTP.
- Correlate with other suspicious events, such as credential dumping or privilege escalation.
- Check for legitimate IT, backup, or data migration activity that may explain the execution.

---

## False Positives

False positives may occur if:

- IT or backup teams are legitimately using Rclone or related scripts for data migration or backup of sensitive files.
- Automated scripts or tools deploy these binaries as part of authorized operations.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the tool or script execution.
2. Review recent activity for signs of data exfiltration or unauthorized transfers.
3. Check for additional indicators of compromise or privilege escalation.
4. Isolate affected systems if malicious activity is confirmed.
5. Remove unauthorized tools and reset credentials as needed.

---

## References

- [MITRE ATT&CK: T1020 – Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)
- [MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-09 | Initial Detection | Created hunt query to detect exfiltration of sensitive file types via Rclone               |
