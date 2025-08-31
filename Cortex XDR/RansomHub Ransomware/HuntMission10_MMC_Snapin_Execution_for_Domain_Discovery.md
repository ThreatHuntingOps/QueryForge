# Detection of Microsoft Management Console (MMC) Snap-ins for Domain Discovery

## Severity or Impact of the Detected Behavior

- **Risk Score:** 75  
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MMC-DomainDiscovery
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of Microsoft Management Console (MMC) snap-ins related to Active Directory and DNS management, such as `dnsmgmt.msc`, `domain.msc`, `dssite.msc`, and `dsa.msc`. These snap-ins are commonly used for domain reconnaissance and administrative tasks. However, their execution outside of normal administrative activity may indicate threat actor reconnaissance, especially during the early stages of an attack or lateral movement.

Detected behaviors include:

- Execution of MMC snap-ins for Active Directory and DNS management
- Attempts to enumerate domain accounts, trusts, and directory structure
- Commonly observed in targeted attacks, red team operations, and internal reconnaissance

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery            | T1087.002   | —            | Account Discovery: Domain Account             |
| TA0007 - Discovery            | T1482       | —            | Domain Trust Discovery                        |

---

## Hunt Query Logic

This query identifies suspicious executions of MMC snap-ins by matching process creation events with command-line arguments referencing `dnsmgmt.msc`, `domain.msc`, `dssite.msc`, or `dsa.msc`. Such activity should be reviewed, especially if performed by non-administrative users or outside of expected maintenance windows.

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
        action_process_image_command_line contains "dnsmgmt.msc"
        or action_process_image_command_line contains "domain.msc"
        or action_process_image_command_line contains "dssite.msc"
        or action_process_image_command_line contains "dsa.msc"
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

- **Required Permissions:** User or attacker must have privileges to execute MMC snap-ins.
- **Required Artifacts:** Process creation logs, command-line arguments.

---

## Considerations

- Investigate the user account and host context for the detected MMC snap-in execution.
- Review for additional signs of domain reconnaissance or privilege escalation.
- Correlate with other suspicious events, such as credential dumping or lateral movement.
- Check for legitimate administrative or troubleshooting activity that may explain the execution.

---

## False Positives

False positives may occur if:

- Administrators are performing legitimate domain or DNS management.
- Automated scripts or IT tools are used for directory or DNS maintenance.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the MMC snap-in execution.
2. Review recent activity for signs of domain reconnaissance or privilege escalation.
3. Check for additional indicators of compromise or lateral movement.
4. Isolate affected systems if malicious activity is confirmed.
5. Review and restrict access to MMC snap-ins as needed.

---

## References

- [MITRE ATT&CK: T1087.002 – Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)
- [MITRE ATT&CK: T1482 – Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect MMC snap-in execution for domain discovery                    |
