# Detection of Impacket-like Remote Execution via Task Scheduler

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Impacket-atexec-v2
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a behavioral pattern consistent with the use of Impacket's `atexec` tool for remote command execution. `atexec` leverages the Windows Task Scheduler service to run commands on a remote host. On the target system, this typically appears as the Task Scheduler service process (`svchost.exe`) spawning a command shell (`cmd.exe`). A key indicator of Impacket's remote execution modules is the redirection of command output to a temporary file on a hidden administrative share (e.g., C$) via the local loopback UNC path (`\\127.0.0.1\C$`). This query identifies this specific parent-child process relationship and command-line structure.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0008 - Lateral Movement     | T1053       | .005         | Scheduled Task/Job: Scheduled Task             |
| TA0002 - Execution            | T1059       | .003         | Command and Scripting Interpreter: Windows Command Shell |

---

## Hunt Query Logic

This query identifies `atexec`-like remote execution by looking for:

- The parent process name `svchost.exe` (hosting the Task Scheduler service).
- The child process name `cmd.exe`.
- Command line arguments indicating output redirection (`>` and `2>&1`).
- Command line arguments containing `\\127.0.0.1\` and `$` which are characteristic of the output file path used by Impacket.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Impacket-like Remote Execution (atexec) (Corrected)
// Description: Detects remote command execution patterns consistent with Impacket's atexec tool, where the Task Scheduler service spawns a shell to execute a command with output redirected to a local administrative share.
// MITRE ATT&CK TTP ID: T1053.005
// MITRE ATT&CK TTP ID: T1059.003

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and actor_process_image_name = "svchost.exe" 
    and action_process_image_name = "cmd.exe" 
    and action_process_image_command_line contains ">" 
    and action_process_image_command_line contains "2>&1" 
    and action_process_image_command_line contains "\\127.0.0.1\" 
    and action_process_image_command_line contains "$" 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The attacker must possess valid credentials with administrative privileges on the target machine to schedule tasks and write to administrative shares.
- **Required Artifacts:** Process creation logs with parent process information and full command-line argument visibility.

---

## Considerations

- This is a high-fidelity indicator of lateral movement using common offensive tools.
- The source of the remote connection should be investigated immediately. The `causality_actor` fields in the query results can help identify the source host.
- The temporary file created on the administrative share (e.g., `C:\__<random>.tmp`) should be collected for forensic analysis if possible.

---

## False Positives

- False positives are very rare. While legitimate remote administration tools exist, this specific pattern of `svchost.exe` -> `cmd.exe` with output redirected to `\\127.0.0.1\[AdminShare]$` is highly characteristic of Impacket.
- Any alert should be investigated as a likely true positive.

---

## Recommended Response Actions

1.  **Isolate:** Immediately isolate both the source and destination endpoints to prevent further lateral movement.
2.  **Investigate:** Analyze the source host to determine the extent of the compromise. Examine the credentials used for the lateral movement and determine if they have been used elsewhere.
3.  **Hunt:** Proactively hunt for the same activity across the environment, originating from or targeting other hosts.
4.  **Remediate:** Remediate the compromised accounts and systems. Ensure the temporary output files are deleted from the administrative shares.
5.  **Monitor:** Enhance monitoring for remote task creation and access to administrative shares.

---

## References

- [MITRE ATT&CK: T1053.005 – Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 2.0     | 2025-07-28 | Query Correction  | Updated query to use `contains` for broader matching. Corrected ATT&CK mapping. |
| 1.0     | 2025-07-28 | Initial Detection | Created hunt query to detect Impacket atexec-like remote execution. |
