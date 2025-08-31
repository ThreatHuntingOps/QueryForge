# Detection of Suspicious Access to FTP and SMTP Client Credentials (Potential DarkCloud Stealer Activity)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-FTP-SMTP-Credential-Access
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious processes accessing FTP and SMTP client credential files, indicative of DarkCloud Stealer activity. The query specifically filters out legitimate FTP and mail client processes to focus on unauthorized or suspicious access attempts.

Detected behaviors include:

- Access to FTP and SMTP client credential files (e.g., recentServers.xml, sitemanager.xml, filezilla.xml, .xml, .ini, .dat) in FileZilla, FTPClient, Outlook, and Thunderbird user data directories
- Correlation of these file access events with non-FTP and non-mail client executable processes

Such techniques are often associated with infostealer malware and credential theft campaigns.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                             |
|------------------------------|--------------|--------------|-----------------------------------------------------------|
| TA0006 - Credential Access   | T1555        | —            | Credentials from Password Stores                          |
| TA0009 - Collection          | T1005        | —            | Data from Local System                                    |

---

## Hunt Query Logic

This query identifies:

- **FTP and SMTP Credential File Access:** Access to FTP and SMTP client credential files.
- **Suspicious Process:** Filters out legitimate FTP and mail client processes to identify unauthorized access.
- **Joins:** Correlates file access events with suspicious processes by agent ID (aid) and process ID (TargetProcessId).

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Detect suspicious processes accessing FTP and SMTP client credential files

#event_simpleName="FileOpen" OR #event_simpleName="FileWritten" 
| TargetFileName=/recentServers\.xml|sitemanager\.xml|filezilla\.xml|\.xml$|\.ini$|\.dat$/i 
| FilePath=/\\AppData\\Roaming\\FileZilla\\.*|\\AppData\\Local\\FTPClient\\.*|\\AppData\\Roaming\\FTPClient\\.*|\\AppData\\Local\\Microsoft\\Outlook\\.*|\\AppData\\Roaming\\Thunderbird\\Profiles\\.*/ 
| join( 
    {#event_simpleName="ProcessRollup2" 
     | ImageFileName=/\.exe$/i 
     | NOT (ImageFileName=/filezilla\.exe|outlook\.exe|thunderbird\.exe/i) 
    } 
    , field=TargetProcessId 
    , key=TargetProcessId 
    , include=[ImageFileName, CommandLine] 
) 
| groupBy([aid, ComputerName], limit=max, function=collect([TargetFileName, FilePath, ImageFileName, CommandLine])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------|---------------------|------------------------|
| Falcon       | N/A              | FileOpen         | File                | File Access            |
| Falcon       | N/A              | FileWritten      | File                | File Creation          |
| Falcon       | N/A              | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to access FTP and SMTP client credential files and execute processes.
- **Required Artifacts:** File access logs, process execution logs.

---

## Considerations

- Investigate the source and legitimacy of processes accessing FTP and SMTP client credential files.
- Analyze command-line arguments and process ancestry for evidence of credential theft.
- Correlate activity with known DarkCloud Stealer indicators or threat intelligence.

---

## False Positives

False positives may occur if:

- Legitimate security tools or backup utilities access FTP or SMTP client credential files for benign purposes.
- Internal tools or automation interact with FTP or mail data for compliance or migration.

---

## Recommended Response Actions

1. Investigate the suspicious processes and their origin.
2. Analyze accessed files for evidence of credential theft or exfiltration.
3. Review command-line arguments and process ancestry for signs of infostealer activity.
4. Monitor for additional signs of compromise or lateral movement.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [Unit 42: DarkCloud Stealer and Obfuscated AutoIt Scripting](https://unit42.paloaltonetworks.com/darkcloud-stealer-and-obfuscated-autoit-scripting/)
- [MITRE ATT&CK: T1555 – Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-21 | Initial Detection | Created hunt query to detect suspicious access to FTP and SMTP client credentials |
