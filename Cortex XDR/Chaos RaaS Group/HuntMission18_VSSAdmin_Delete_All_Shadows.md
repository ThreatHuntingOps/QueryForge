# Detection of Volume Shadow Copy Deletion via vssadmin

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-VSSAdmin-DeleteAllShadows
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the execution of the `vssadmin.exe` utility to delete all volume shadow copies from the system. This is a critical and very common ransomware TTP used to inhibit system recovery, preventing administrators from restoring encrypted files from local backups. The Chaos ransomware was explicitly observed performing this action. This activity is highly anomalous outside of specific, planned maintenance and is a strong indicator of an impending impact stage.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0040 - Impact               | T1490       | —            | Inhibit System Recovery                        |

---

## Hunt Query Logic

This query identifies this destructive behavior by looking for the specific command used to delete all shadow copies at once:
- The execution of `vssadmin.exe`.
- The presence of the `delete` and `shadows` arguments.
- The inclusion of the `/all` switch, which specifies that all existing shadow copies should be deleted.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Volume Shadow Copy Deletion to Inhibit System Recovery
// Description: Detects the use of vssadmin.exe to delete all volume shadow copies, a common ransomware technique to prevent system recovery.
// MITRE ATT&CK TTP ID: T1490

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "vssadmin.exe" 
    and action_process_image_command_line contains "delete" 
    and action_process_image_command_line contains "shadows" 
    and action_process_image_command_line contains "/all" 
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

- **Required Permissions:** The attacker must have administrative privileges on the host to delete shadow copies.
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- **Precursor to Impact:** This is a very strong indicator that a major impact event, such as file encryption, is imminent. Response must be immediate.
- **High-Confidence Alert:** There are very few legitimate reasons to delete all shadow copies from a system in this manner, especially on a server.
- **Parent Process is Key:** The parent process that spawned `vssadmin.exe` is the immediate culprit (e.g., the ransomware executable or a deployment script) and must be investigated.

---

## False Positives

- False positives are very rare. Some backup software or storage administration scripts may perform this action during major maintenance or reconfiguration, but this is not a routine operation. Any alert should be treated as a likely true positive and investigated with urgency.

---

## Recommended Response Actions

1.  **Isolate Host Immediately:** This is a critical, time-sensitive alert. Isolate the host from the network without delay to prevent the spread of ransomware if it has not already executed.
2.  **Assume Imminent Impact:** Treat this as a "break glass" event. The system is likely in the process of being ransomed.
3.  **Investigate Causality:** Immediately identify and analyze the parent process that executed the `vssadmin` command.
4.  **Hunt for Parent Process:** Take the hash of the parent process and hunt for it across the entire environment to identify other compromised systems.
5.  **Verify Off-Host Backups:** While local recovery points may be gone, immediately verify the integrity and accessibility of your off-host and offline backups.

---

## References

- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created hunt query to detect the deletion of all volume shadow copies. |
