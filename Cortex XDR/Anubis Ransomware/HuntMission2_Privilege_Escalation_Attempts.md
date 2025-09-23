# Detection of Anubis Ransomware Privilege Escalation Attempts and Interactive Prompts

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnubisPrivilegeEscalation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects suspicious process executions that attempt to detect or escalate privileges, as observed in Anubis ransomware campaigns. The detection focuses on command-line parameters and interactive prompt strings, such as unique messages in process command lines or window titles. These behaviors are indicative of malware seeking SYSTEM-level access or interacting with users to gain higher privileges, which is a critical step in ransomware deployment and impact maximization.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                             |
|------------------------------|-------------|--------------|-----------------------------------------------------------|
| TA0006 - Credential Access    | T1078       | —            | Valid Accounts                                            |
| TA0002 - Execution           | T1055       | —            | Process Injection                                         |
| TA0004 - Privilege Escalation| T1548.002   | —            | Abuse Elevation Control Mechanism: Bypass UAC             |
| TA0005 - Defense Evasion     | T1564.001   | —            | Hide Artifacts: Hidden Files and Directories              |

---

## Hunt Query Logic

This query identifies process execution events where the command line or window title contains evidence of privilege checking, elevation attempts, or interactive prompts typical of Anubis ransomware. These patterns are rarely seen in legitimate software and are highly suspicious. The query can be further refined by correlating with parent process, user context, or event frequency.

---

## Hunt Query Syntax

**Query Language:** XQL (XDR Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Process Command Line with Privilege Escalation Messages
// Description: Detects processes with command lines containing messages about admin privilege detection or elevation attempts, which may indicate privilege escalation or suspicious tool usage.
// MITRE ATT&CK TTP ID: T1548

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_command_line contains "Admin privileges detected. Attempting to elevate to SYSTEM"
        or action_process_image_command_line contains "No admin privileges. Start process anyway?"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute processes with custom command-line arguments or prompt messages.
- **Required Artifacts:** Process creation logs with full command-line and window title capture.

---

## Considerations

- Correlate with parent process and user context for additional signs of privilege escalation.
- Review frequency and timing of these events to identify automated or scripted attacks.
- Investigate for additional indicators of process injection or artifact hiding.

---

## False Positives

False positives are unlikely but may occur if:
- Legitimate administrative tools use similar interactive prompts (rare).
- Custom internal scripts or IT tools are misconfigured to use these messages.

---

## Recommended Response Actions

1. Isolate the affected endpoint immediately.
2. Investigate the process tree and parent process for initial access vectors.
3. Review for signs of privilege escalation or SYSTEM-level access.
4. Collect forensic artifacts (memory, disk, logs) for further analysis.
5. Initiate incident response and recovery procedures if ransomware activity is confirmed.

---

## References

- [MITRE ATT&CK: T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1548.002 – Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)
- [MITRE ATT&CK: T1564.001 – Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/)
- [Anubis: A Closer Look at an Emerging Ransomware with Built-in Wiper](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-20 | Initial Detection | Created hunt query to detect Anubis ransomware privilege escalation attempts and interactive prompts |
