# Detection of Remote Process Execution via WMIC

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WMIC-RemoteExec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the use of the Windows Management Instrumentation Command-line utility (`wmic.exe`) to create a process on a remote machine. This is a powerful "living-off-the-land" technique for lateral movement and remote execution. The Chaos ransomware group was observed using this exact method to launch their encryptor payload on other hosts in the network. The use of the `/node:` switch to specify a target and the `process call create` command is a high-fidelity indicator of this activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0008 - Lateral Movement     | T1047       | —            | Windows Management Instrumentation             |
| TA0002 - Execution            | T1047       | —            | Windows Management Instrumentation             |

---

## Hunt Query Logic

This query identifies remote process creation via WMIC by looking for:
- The execution of `wmic.exe`.
- The presence of the `/node:` switch, which specifies the remote target host.
- The combination of `process`, `call`, and `create` in the command line, which instructs WMI to start a new process.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Remote Process Creation using WMIC
// Description: Detects the use of "wmic.exe" with the "/node" and "process call create" parameters to execute a process on a remote host, a key lateral movement TTP for Chaos RaaS.
// MITRE ATT&CK TTP ID: T1047

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "wmic.exe" 
    and action_process_image_command_line contains "/node:" 
    and action_process_image_command_line contains "process" 
    and action_process_image_command_line contains "call" 
    and action_process_image_command_line contains "create" 
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

- **Required Permissions:** The attacker must have administrative privileges on the remote target host and the appropriate firewall exceptions for DCOM/RPC.
- **Required Artifacts:** Process creation logs with full command-line argument visibility on the source host.

---

## Considerations

- **Critical IOCs:** The command line (`action_process_image_command_line`) contains two critical IOCs: the target host (after `/node:`) and the command that was executed remotely.
- **Event on Target:** This hunt detects the command on the *source* host. On the *target* host, you would see the executed process being spawned by `WmiPrvSE.exe`. Correlating these two events provides a complete picture of the lateral movement.

---

## False Positives

False positives can occur when:
- Legitimate remote administration scripts use WMIC for software deployment or management.
- Enterprise management tools (e.g., SCCM) leverage WMIC for remote tasks.
The context is critical. An administrator running a known script is different from `wmic.exe` being spawned by an unusual parent process to launch `powershell.exe` on a remote server.

---

## Recommended Response Actions

1.  **Isolate Both Hosts:** Immediately isolate both the source (`agent_hostname`) and the destination (`/node:`) hosts to contain the threat.
2.  **Analyze Command:** Examine the command line to understand what process was executed on the remote host. This will reveal the attacker's immediate objective.
3.  **Investigate Source:** Analyze the source host to understand how the attacker gained access and was able to launch the WMIC command.
4.  **Investigate Destination:** Analyze the destination host for signs of follow-on activity from the remotely executed process.
5.  **Review Credentials:** The credentials used for this action are compromised. They must be reset, and their other activities should be reviewed.

---

## References

- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created hunt query to detect remote process creation via WMIC.       |
