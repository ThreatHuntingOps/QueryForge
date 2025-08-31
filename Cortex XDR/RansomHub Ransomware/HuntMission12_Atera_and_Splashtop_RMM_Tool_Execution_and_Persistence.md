# Detection of Atera and Splashtop RMM Tool Execution and Persistence

## Severity or Impact of the Detected Behavior

- **Risk Score:** 85  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RMM-Tool-Exec-Persistence
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution and persistence of remote monitoring and management (RMM) tools such as Atera and Splashtop. These tools are frequently abused by threat actors for command and control (C2), remote access, and maintaining persistence within compromised environments. The query identifies process execution and service installation events related to these tools, including any process or command line referencing "atera" or "splashtop." Such activity is a strong indicator of hands-on-keyboard attacker presence, especially when observed outside of authorized IT operations.

Detected behaviors include:

- Execution of Atera or Splashtop binaries or processes
- Command lines referencing Atera or Splashtop
- Installation or persistence of RMM tools as services
- Potential use of RMM tools for C2, lateral movement, or data exfiltration

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution            | T1219       | —            | Remote Access Software                        |
| TA0011 - Command and Control  | T1071       | —            | Application Layer Protocol                    |
| TA0004 - Privilege Escalation | T1543.003   | —            | Create or Modify System Process: Windows Service |

---

## Hunt Query Logic

This query identifies suspicious process execution events where the file name or command line references Atera or Splashtop. It is designed to catch both direct execution and persistence mechanisms (such as service installation) for these RMM tools.

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
        (action_process_image_name contains "atera" and action_process_image_name contains ".exe")
        or (action_process_image_name contains "splashtop" and action_process_image_name contains ".exe")
        or action_process_image_command_line contains "atera"
        or action_process_image_command_line contains "splashtop"
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

- **Required Permissions:** User or attacker must have privileges to execute binaries and install services.
- **Required Artifacts:** Process creation logs, command-line arguments, service installation logs.

---

## Considerations

- Investigate the user account and host context for the detected RMM tool activity.
- Review for additional signs of C2, lateral movement, or data exfiltration.
- Correlate with other suspicious events, such as new service creation or external network connections.
- Check for legitimate IT or support activity that may explain the execution.

---

## False Positives

False positives may occur if:

- IT administrators are legitimately deploying or using Atera or Splashtop for remote support.
- Automated software deployment tools install or update these services as part of normal operations.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the RMM tool execution or installation.
2. Validate the legitimacy of the RMM tool deployment with IT operations.
3. Review for additional signs of compromise, persistence, or C2 activity.
4. Remove unauthorized RMM tools and reset credentials if malicious activity is confirmed.
5. Monitor for further attempts to establish remote access or persistence.

---

## References

- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK: T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK: T1543.003 – Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect Atera and Splashtop RMM tool execution and persistence        |
