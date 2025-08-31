# Detection of Suspicious Access to Browser Credential Files (Potential DarkCloud Stealer Activity)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Browser-Credential-Access
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious processes accessing sensitive browser credential files such as `logins.json`, `key4.db`, `signons.sqlite`, and other credential databases commonly targeted by DarkCloud Stealer. The query specifically filters out legitimate browser processes to focus on unauthorized or suspicious access attempts.

Detected behaviors include:

- Access to browser credential files in Chrome, Firefox, Edge, Brave, and Opera user data directories
- Correlation of these file access events with non-browser executable processes

Such techniques are often associated with infostealer malware and credential theft campaigns.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                             |
|------------------------------|--------------|--------------|-----------------------------------------------------------|
| TA0006 - Credential Access   | T1555.003    | —            | Credentials from Web Browsers                             |
| TA0009 - Collection          | T1005        | —            | Data from Local System                                    |

---

## Hunt Query Logic

This query identifies:

- **Credential File Access:** Access to sensitive browser credential files.
- **Suspicious Process:** Filters out legitimate browser processes to identify unauthorized access.
- **Joins:** Correlates file access events with suspicious processes by agent ID (aid) and process ID (TargetProcessId).

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Detect suspicious processes accessing browser credential files

#event_simpleName="FileOpen" OR #event_simpleName="FileWritten" 
| TargetFileName=/logins\.json|key4\.db|signons\.sqlite|Login Data|Cookies|Web Data|places\.sqlite/i 
| FilePath=/\\AppData\\Local\\Google\\Chrome\\User Data\\.*|\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\.*|\\AppData\\Local\\Microsoft\\Edge\\User Data\\.*|\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\.*|\\AppData\\Local\\Opera Software\\Opera Stable\\.*/ 
| join( 
    {#event_simpleName="ProcessRollup2" 
     | ImageFileName=/\.exe$/i 
     | NOT (ImageFileName=/chrome\.exe|firefox\.exe|msedge\.exe|brave\.exe|opera\.exe/i) 
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

- **Required Permissions:** User or attacker must be able to access browser credential files and execute processes.
- **Required Artifacts:** File access logs, process execution logs.

---

## Considerations

- Investigate the source and legitimacy of processes accessing browser credential files.
- Analyze command-line arguments and process ancestry for evidence of credential theft.
- Correlate activity with known DarkCloud Stealer indicators or threat intelligence.

---

## False Positives

False positives may occur if:

- Legitimate security tools or backup utilities access browser credential files for benign purposes.
- Internal tools or automation interact with browser data for compliance or migration.

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
- [MITRE ATT&CK: T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-20 | Initial Detection | Created hunt query to detect suspicious access to browser credential files |
