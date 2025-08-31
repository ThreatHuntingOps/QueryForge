# Detection of Rclone, nocmd.vbs, and rcl.bat Execution for Data Exfiltration

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Rclone-Exfil-Script
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the execution of Rclone and its associated helper scripts (`nocmd.vbs`, `rcl.bat`), which are commonly used for automated data exfiltration via SFTP or cloud storage. Rclone is a legitimate open-source tool for managing files on cloud storage, but it is frequently abused by threat actors to exfiltrate sensitive data. The presence of these binaries or scripts in process creation logs is a strong indicator of data exfiltration activity, especially when observed in conjunction with suspicious network connections or large file transfers.

Detected behaviors include:

- Execution of `rclone.exe`, `nocmd.vbs`, or `rcl.bat`
- Attempts to automate data exfiltration to cloud storage or SFTP servers
- Commonly observed in ransomware, APT, and data theft campaigns

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0010 - Exfiltration         | T1048       | —            | Exfiltration Over Alternative Protocol        |
| TA0010 - Exfiltration         | T1567.002   | —            | Exfiltration Over Web Service: Exfiltration to Cloud Storage |

---

## Hunt Query Logic

This query identifies suspicious process creation events for `rclone.exe`, `nocmd.vbs`, or `rcl.bat`. Such activity is rarely seen in legitimate environments and should be investigated, especially if observed alongside large outbound data transfers.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "rclone.exe"
        or action_process_image_name = "nocmd.vbs"
        or action_process_image_name = "rcl.bat"
    )
| fields _time, agent_hostname, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to execute binaries and scripts.
- **Required Artifacts:** Process creation logs, command-line arguments, network connection logs.

---

## Considerations

- Investigate the user account and host context for the detected tool or script execution.
- Review for additional signs of data exfiltration, such as large outbound transfers or connections to cloud storage/SFTP.
- Correlate with other suspicious events, such as credential dumping or privilege escalation.
- Check for legitimate IT or backup activity that may explain the execution.

---

## False Positives

False positives may occur if:

- IT or backup teams are legitimately using Rclone or related scripts for data migration or backup.
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

- [MITRE ATT&CK: T1048 – Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK: T1567.002 – Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect Rclone, nocmd.vbs, and rcl.bat execution for data exfiltration|
