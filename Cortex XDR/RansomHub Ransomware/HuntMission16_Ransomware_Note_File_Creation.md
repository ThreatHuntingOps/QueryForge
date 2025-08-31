# Detection of Ransomware Note File Creation

## Severity or Impact of the Detected Behavior

- **Risk Score:** 95  
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Ransom-Note-FileCreate
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the creation of files commonly used as ransom notes, such as `README.txt`, `HOW_TO_DECRYPT.txt`, `RECOVER_FILES.html`, or any file containing “ransom” or “decrypt” in its name. The presence of these files is a strong indicator of ransomware impact, as threat actors typically drop ransom notes to instruct victims on payment and recovery steps. This query leverages regex to match a variety of ransom note naming conventions observed across ransomware families.

Detected behaviors include:

- Creation of ransom note files with names like `README.txt`, `HOW_TO_DECRYPT.txt`, `RECOVER_FILES.html`
- Creation of files containing “ransom” or “decrypt” in their names
- Commonly observed in ransomware campaigns to notify victims and demand payment

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact                     |
| TA0040 - Impact               | T1491       | —            | Defacement                                    |

---

## Hunt Query Logic

This query identifies suspicious file creation events where the filename matches common ransom note patterns. Such activity is rarely seen in legitimate environments and should be investigated immediately, especially if observed alongside other ransomware indicators.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        (action_file_name contains "readme" and action_file_name contains ".txt")
        or (action_file_name contains "how_to_decrypt" and action_file_name contains ".txt")
        or (action_file_name contains "recover_files" and action_file_name contains ".html")
        or (action_file_name contains "ransom" and action_file_name contains ".txt")
        or (action_file_name contains "decrypt" and action_file_name contains ".txt")
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

- **Required Permissions:** User or attacker must have privileges to write files to the target directory.
- **Required Artifacts:** File creation logs, file path and name details, host and user context.

---

## Considerations

- Investigate the user account and host context for the detected file creation.
- Review for additional signs of ransomware deployment, such as simultaneous ransom note creation on multiple hosts.
- Correlate with other suspicious events, such as shadow copy deletion, event log clearing, or encryption activity.
- Check for legitimate software or scripts that may create similarly named files.

---

## False Positives

False positives may occur if:

- IT or security teams are testing ransomware detection or response.
- Automated scripts or tools create files with similar names for legitimate purposes.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the file creation.
2. Review recent activity for signs of ransomware deployment or system compromise.
3. Check for additional indicators of compromise or privilege escalation.
4. Isolate affected systems if malicious activity is confirmed.
5. Restore data from secure backups and review recovery procedures.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1491 – Defacement](https://attack.mitre.org/techniques/T1491/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect ransomware note file creation                                 |
