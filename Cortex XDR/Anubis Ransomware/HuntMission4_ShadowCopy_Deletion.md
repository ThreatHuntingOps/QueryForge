# Detection of Anubis Ransomware Inhibiting System Recovery via Shadow Copy Deletion

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnubisShadowCopyDeletion
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects the execution of the `vssadmin` utility with parameters used to delete all Volume Shadow Copies, a technique commonly employed by ransomware—including Anubis—to inhibit system recovery and prevent file restoration. The presence of `/delete shadows`, `/for=`, `/all`, and `/quiet` in the command line is highly suspicious and rarely seen in legitimate administrative activity. Early detection of this behavior is critical for preventing irreversible data loss.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1490       | —            | Inhibit System Recovery                       |
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |

---

## Hunt Query Logic

This query identifies process execution events where `vssadmin.exe` is used to delete shadow copies with the specific parameters observed in Anubis ransomware attacks. Such activity is a strong indicator of ransomware attempting to prevent recovery and should be investigated immediately. The query can be further refined by correlating with user context, parent process, or frequency of these events.

---

## Hunt Query Syntax

**Query Language:** XQL (XDR Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Vssadmin Deleting All Shadows Quietly
// Description: Detects vssadmin.exe processes attempting to delete all shadow copies quietly, which is a common ransomware or destructive activity indicator.
// MITRE ATT&CK TTP ID: T1490

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "vssadmin.exe"
        or action_process_image_path contains "vssadmin.exe"
    )
    and action_process_image_command_line contains "delete shadows"
    and action_process_image_command_line contains "/for="
    and action_process_image_command_line contains "/all"
    and action_process_image_command_line contains "/quiet"
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

- **Required Permissions:** User or attacker must have administrative privileges to execute `vssadmin.exe` with shadow copy deletion parameters.
- **Required Artifacts:** Process creation logs with full command-line capture.

---

## Considerations

- Correlate with other signs of ransomware activity, such as file encryption or privilege escalation.
- Review the process tree and parent process for initial access vectors.
- Investigate the timing and frequency of shadow copy deletion attempts.

---

## False Positives

False positives are extremely rare, but may occur if:
- Legitimate disaster recovery or backup scripts are misconfigured to use these parameters (uncommon).
- IT administrators perform mass shadow copy deletions outside of standard maintenance windows.

---

## Recommended Response Actions

1. Isolate the affected endpoint immediately to prevent further impact.
2. Investigate the process tree and user context for signs of compromise.
3. Review for additional ransomware behaviors, such as file encryption or privilege escalation.
4. Collect forensic artifacts (memory, disk, logs) for further analysis.
5. Initiate incident response and recovery procedures as soon as possible.

---

## References

- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [Anubis: A Closer Look at an Emerging Ransomware with Built-in Wiper](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-23 | Initial Detection | Created hunt query to detect Anubis ransomware inhibiting system recovery via shadow copy deletion |
