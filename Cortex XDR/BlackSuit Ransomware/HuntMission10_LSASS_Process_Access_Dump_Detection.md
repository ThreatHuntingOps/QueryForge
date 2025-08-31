# Detection of LSASS Process Access and Dump File Creation

## Severity or Impact of the Detected Behavior

- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-LSASS-Dump-Detection
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects suspicious access to the LSASS process and the creation of dump files, which is a strong indicator of credential dumping activity. Tools like Mimikatz, Cobalt Strike, and CreBandit often target LSASS to extract credentials. Detected behaviors include:

- Process command lines referencing `lsass`, `procdump`, `comsvcs.dll`, `taskmgr`, `dumpert`, `sekurlsa`, or `crebandit`
- Command lines indicating dump file creation (e.g., `.dmp`, `dump`)
- Full process and user context for investigation

These techniques are associated with credential access, process injection, and defense evasion.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0006 - Credential Access   | T1003       | —            | OS Credential Dumping                         |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                             |
| TA0005 - Defense Evasion     | T1218.011   | —            | Signed Binary Proxy Execution: Rundll32        |

---

## Hunt Query Logic

This query identifies suspicious LSASS access and dump file creation by looking for:

- Process command lines referencing LSASS or common credential dumping tools
- Command lines indicating dump file creation
- Full process and user context for triage

These patterns are indicative of credential dumping activity.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: LSASS Process Access and Dump File Creation
// Description: Detects suspicious access to the LSASS process and creation of dump files, a strong indicator of credential dumping activity (e.g., Mimikatz, Cobalt Strike, CreBandit).
// MITRE ATT&CK TTP ID: T1003

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_command_line contains "lsass"
        or action_process_image_command_line contains "procdump"
        or action_process_image_command_line contains "comsvcs.dll"
        or action_process_image_command_line contains "taskmgr"
        or action_process_image_command_line contains "dumpert"
        or action_process_image_command_line contains "sekurlsa"
        or action_process_image_command_line contains "crebandit"
    )
    and (
        action_process_image_command_line contains ".dmp"
        or action_process_image_command_line contains "dump"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name   | ATT&CK Data Source  | ATT&CK Data Component  |
|----------------|--------------|---------------------|------------------------|
| Cortex XSIAM   | xdr_data     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to access LSASS and create dump files.
- **Required Artifacts:** Process creation logs, command-line arguments, and file creation events.

---

## Considerations

- Review the source and context of the process and command line for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent credential access or lateral movement.

---

## False Positives

False positives may occur if:

- IT administrators or legitimate tools access LSASS for troubleshooting or memory analysis.
- Automated deployment tools or scripts generate and execute these commands for legitimate purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review user activity and system logs for signs of compromise or credential access.
3. Analyze any subsequent network connections or file transfers.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious LSASS access and dump file creation attempts.

---

## References

- [MITRE ATT&CK: T1003 – OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1218.011 – Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect LSASS process access and dump file creation                   |
