# Detection of Ransomware Propagation via SMB and Random Executable Creation

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Ransomware-SMB-Propagation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the creation of executable files with random names (e.g., `C:\[random_string].exe`) on multiple hosts, which may indicate ransomware propagation via SMB (Server Message Block) or Windows Admin Shares. Attackers often use randomly named executables to evade signature-based detection and propagate ransomware or other malicious payloads across the network. The query leverages regex to match suspicious file creation patterns and can be further tuned to match the specific filename conventions observed in your environment.

Detected behaviors include:

- Creation of `.exe` files with random alphanumeric names in the root of `C:\`
- Potential lateral movement and propagation of ransomware via SMB shares
- Commonly observed in ransomware campaigns and worm-like malware outbreaks

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0011 - Command and Control  | T1105       | —            | Ingress Tool Transfer                         |
| TA0008 - Lateral Movement     | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares     |
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact                     |

---

## Hunt Query Logic

This query identifies suspicious file creation events where the filename matches a random alphanumeric pattern (6 or more characters) ending in `.exe`, or where an executable is created directly in the root of `C:\`. Such activity is rarely seen in legitimate environments and should be investigated, especially if observed on multiple hosts in a short time window.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=FileCreate    

| (FileName = /[a-zA-Z0-9]{6,}\.exe/i OR FilePath = "C:\\*.exe") 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | FileCreate       | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to write files to the target directory.
- **Required Artifacts:** File creation logs, file path and name details, host and user context.

---

## Considerations

- Investigate the user account and host context for the detected file creation.
- Review for additional signs of ransomware propagation, such as simultaneous file creation on multiple hosts.
- Correlate with other suspicious events, such as SMB traffic, credential dumping, or privilege escalation.
- Tune the regex pattern to match the specific random filename conventions observed in your environment.

---

## False Positives

False positives may occur if:

- Legitimate software deployment or update tools create executables with random names.
- IT or security teams are testing or deploying custom scripts or binaries.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the file creation.
2. Review recent activity for signs of lateral movement or ransomware deployment.
3. Check for additional indicators of compromise or privilege escalation.
4. Isolate affected systems if malicious activity is confirmed.
5. Remove unauthorized executables and restore affected files from backups if needed.

---

## References

- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-09 | Initial Detection | Created hunt query to detect ransomware propagation via SMB and random executable creation  |
