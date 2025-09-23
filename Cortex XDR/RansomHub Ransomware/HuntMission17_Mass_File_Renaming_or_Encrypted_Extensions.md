# Detection of Mass File Renaming or Creation of Encrypted File Extensions

## Severity or Impact of the Detected Behavior

- **Risk Score:** 98  
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-File-Encryption-Artifact
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the creation or renaming of files with extensions commonly associated with ransomware encryption, such as `.locked`, `.encrypted`, `.ransomhub`, `.crypt`, or `.enc`. The sudden appearance of files with these extensions is a strong indicator of ransomware activity, as threat actors often append unique or campaign-specific extensions to encrypted files. The query can be tuned to include additional extensions based on the ransomware family observed in your environment.

Detected behaviors include:

- Creation or renaming of files with known ransomware-related extensions
- Mass file renaming or extension changes in a short time window
- Commonly observed in ransomware campaigns to signal successful encryption

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact                     |

---

## Hunt Query Logic

This query identifies suspicious file creation events where the filename ends with extensions commonly used by ransomware. Such activity is rarely seen in legitimate environments and should be investigated immediately, especially if observed on multiple hosts or directories.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_file_name contains ".locked"
        or action_file_name contains ".encrypted"
        or action_file_name contains ".ransomhub"
        or action_file_name contains ".crypt"
        or action_file_name contains ".enc"
    )
| fields _time, agent_hostname, action_file_name, action_file_path, action_file_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to write or rename files.
- **Required Artifacts:** File creation logs, file path and name details, host and user context.

---

## Considerations

- Investigate the user account and host context for the detected file creation or renaming.
- Review for additional signs of ransomware deployment, such as ransom note creation or shadow copy deletion.
- Correlate with other suspicious events, such as process execution or privilege escalation.
- Tune the extension list to match ransomware families observed in your environment.

---

## False Positives

False positives may occur if:

- Legitimate software or scripts create files with similar extensions for backup or encryption purposes.
- IT or security teams are testing ransomware detection or response.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the file creation or renaming.
2. Review recent activity for signs of ransomware deployment or system compromise.
3. Check for additional indicators of compromise or privilege escalation.
4. Isolate affected systems if malicious activity is confirmed.
5. Restore data from secure backups and review recovery procedures.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect mass file renaming or creation of encrypted file extensions    |
