# Detection of Anubis Ransomware Execution via Suspicious Command-Line Parameters

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnubisRansomware
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects suspicious process executions that match unique command-line parameters associated with Anubis ransomware. The detection focuses on the presence of `/KEY=`, `/elevated`, `/WIPEMODE`, `/PFAD=`, and `/PATH=` in process command lines. These parameters are rarely used by legitimate software and are indicative of ransomware activity, especially those involving privilege escalation and targeted encryption. Early detection of these patterns can help prevent or mitigate ransomware impact.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                 |
|------------------------------|------------|--------------|-----------------------------------------------|
| TA0002 - Execution            | T1059      | —            | Command and Scripting Interpreter             |
| TA0040 - Impact               | T1486      | —            | Data Encrypted for Impact                     |
| TA0004 - Privilege Escalation | T1068      | —            | Exploitation for Privilege Escalation         |
| TA0005 - Defense Evasion      | T1562.001  | —            | Impair Defenses: Disable or Modify Tools      |

---

## Hunt Query Logic

This query identifies process execution events where the command line contains one or more of the Anubis-specific parameters. These patterns are highly suspicious and rarely seen in legitimate software. The query can be further refined by adding filters for suspicious parent processes, file paths, or user context if additional intelligence is available.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Process Command Line with Suspicious Switches
// Description: Detects processes with command lines containing suspicious switches such as /key=, /elevated, /wipemode, /pfad=, or /path=, which may indicate privilege escalation, staging, or data exfiltration attempts.
// MITRE ATT&CK TTP ID: T1548

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_command_line contains "/key="
        or action_process_image_command_line contains "/elevated"
        or action_process_image_command_line contains "/wipemode"
        or action_process_image_command_line contains "/pfad="
        or action_process_image_command_line contains "/path="
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

- **Required Permissions:** User or attacker must be able to execute processes with custom command-line arguments.
- **Required Artifacts:** Process creation logs with full command-line capture.

---

## Considerations

- Review the parent process and user context for additional signs of compromise.
- Correlate with file creation, modification, or deletion events for ransomware behavior.
- Investigate any privilege escalation or defense evasion attempts in parallel.

---

## False Positives

False positives are unlikely but may occur if:
- Legitimate administrative tools use similar command-line parameters (rare).
- Custom internal scripts or tools are misconfigured to use these flags.

---

## Recommended Response Actions

1. Isolate the affected endpoint immediately.
2. Investigate the process tree and parent process for initial access vectors.
3. Review for signs of file encryption or deletion.
4. Collect forensic artifacts (memory, disk, logs) for further analysis.
5. Initiate incident response and recovery procedures if ransomware activity is confirmed.

---

## References

- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [Anubis: A Closer Look at an Emerging Ransomware with Built-in Wiper](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-20 | Initial Detection | Created hunt query to detect Anubis ransomware execution via suspicious command-line parameters |
