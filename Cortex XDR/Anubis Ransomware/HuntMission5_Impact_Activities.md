# Detection of Anubis Ransomware Impact Activities: Shadow Copy Deletion, Service Stopping, and ECIES-based Encryption

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnubisImpactActivities
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Extremely Low

---

## Hunt Analytics

This hunt detects key impact behaviors associated with Anubis ransomware, including the deletion of Volume Shadow Copies to inhibit recovery, the stopping or disabling of critical services, and the use of Go-based ECIES encryption routines. These actions are strong indicators of ransomware activity and can help surface attacks in progress or post-compromise impact. The detection logic combines multiple high-fidelity signals to minimize false positives and maximize early detection of ransomware impact.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1490       | —            | Inhibit System Recovery                       |
| TA0040 - Impact              | T1489       | —            | Service Stop                                  |
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |

---

## Hunt Query Logic

This query identifies process execution events where:
- `vssadmin.exe` is used to delete shadow copies with specific parameters (T1490)
- Processes attempt to stop, disable, or terminate services (T1489)
- Command lines reference ECIES encryption, elliptic curve cryptography, or known ransomware-related Go packages (T1486)

These behaviors are rarely seen in legitimate administrative activity and are highly suspicious in most environments. For more targeted detection, you can further refine the query with specific service names, process names, or by correlating with known IoCs.

---

## Hunt Query Syntax

**Query Language:** XQL (XDR Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM platforms

```xql
// Title: Vssadmin Shadow Deletion with Stop/Disable/Terminate and ECIES/Evilbyte/Prince Indicators
// Description: Detects vssadmin.exe processes deleting shadow copies with additional stop/disable/terminate actions and references to ECIES, elliptic curve, evilbyte, prince, or related GitHub, which may indicate advanced ransomware or destructive activity.
// MITRE ATT&CK TTP ID: T1490

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        (
            action_process_image_name = "vssadmin.exe"
            or action_process_image_path contains "vssadmin.exe"
        )
        and action_process_image_command_line contains "delete shadows"
        and action_process_image_command_line contains "/for="
        and action_process_image_command_line contains "/all"
        and action_process_image_command_line contains "/quiet"
        and (
            action_process_image_command_line contains "stop"
            or action_process_image_command_line contains "disable"
            or action_process_image_command_line contains "terminate"
        )
        and (
            action_process_image_command_line contains "ecies"
            or action_process_image_command_line contains "elliptic curve"
            or action_process_image_command_line contains "github.com/ecies"
            or action_process_image_command_line contains "evilbyte"
            or action_process_image_command_line contains "prince"
        )
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

- **Required Permissions:** User or attacker must have administrative privileges to execute service control or shadow copy deletion commands.
- **Required Artifacts:** Process creation logs with full command-line capture.

---

## Considerations

- Correlate with other signs of ransomware activity, such as privilege escalation or file encryption.
- Review the process tree and parent process for initial access vectors.
- Investigate the timing and frequency of service stop or shadow copy deletion attempts.
- Look for additional indicators of Go-based ransomware, such as unique file names or network activity.

---

## False Positives

False positives are extremely rare, but may occur if:
- Legitimate IT maintenance or disaster recovery scripts are misconfigured to use these parameters (uncommon).
- Security or backup tools reference ECIES or related cryptography libraries for legitimate purposes (rare).

---

## Recommended Response Actions

1. Isolate the affected endpoint immediately to prevent further impact.
2. Investigate the process tree and user context for signs of compromise.
3. Review for additional ransomware behaviors, such as file encryption or privilege escalation.
4. Collect forensic artifacts (memory, disk, logs) for further analysis.
5. Initiate incident response and recovery procedures as soon as possible.
6. Correlate with threat intelligence for known IoCs and ransomware variants.

---

## References

- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [Anubis: A Closer Look at an Emerging Ransomware with Built-in Wiper](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-24 | Initial Detection | Created hunt query to detect Anubis ransomware impact activities: shadow copy deletion, service stopping, and ECIES-based encryption |
