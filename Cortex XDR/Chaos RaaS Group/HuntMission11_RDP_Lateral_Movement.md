# Detection of Interactive RDP Session for Lateral Movement

## Severity or Impact of the Detected Behavior
- **Risk Score:** 65
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-RDP-LateralMovement
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** High

---

## Hunt Analytics

This hunt detects the execution of the Microsoft Terminal Services Client (`mstsc.exe`), the command-line tool for initiating a Remote Desktop Protocol (RDP) session. The Chaos ransomware group, like many other threat actors, uses RDP to move laterally from a compromised host to other systems on the network. While RDP is a legitimate administrative tool, tracking its initiation with a specified target (the `/v:` parameter) can help identify suspicious or unauthorized remote access, especially when originating from non-administrative workstations or performed by non-privileged users.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0008 - Lateral Movement     | T1021       | .001         | Remote Services: Remote Desktop Protocol       |

---

## Hunt Query Logic

This query identifies the initiation of a targeted RDP session by looking for:
- The execution of the `mstsc.exe` process.
- The presence of the `/v:` command-line parameter, which explicitly defines the destination host for the RDP connection.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: RDP Client Execution for Lateral Movement
// Description: Detects the execution of mstsc.exe with a specified target host, a common technique for lateral movement via RDP.
// MITRE ATT&CK TTP ID: T1021.001

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "mstsc.exe" 
    and action_process_image_command_line contains "/v:" 
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

- **Required Permissions:** The user or attacker needs valid credentials for the destination host and network access to it over port 3389.
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- **High False Positive Rate:** This activity is extremely common in most environments for legitimate administration. The value of this hunt comes from analyzing the context, not from the alert itself.
- **Context is Key:** An alert's significance depends on:
    - **Source:** Is `agent_hostname` an administrator's jump box or a standard user's workstation?
    - **User:** Is `actor_effective_username` a privileged administrator or a standard user?
    - **Destination:** What is the target host specified after `/v:`? Is it a critical server?
- **Baseline Activity:** Understanding normal RDP patterns in your environment is crucial to identifying anomalies.

---

## False Positives

False positives are expected and will occur any time a user or administrator legitimately uses the RDP client to connect to another machine. This is a very common action.

---

## Recommended Response Actions

1.  **Verify Legitimacy:** The primary action is to determine if the RDP session is authorized. Check the source user and host against their expected roles and responsibilities.
2.  **Analyze Context:** If the RDP session is unusual (e.g., a user from finance RDPs to a domain controller), it requires immediate investigation.
3.  **Investigate Source and Destination:** If the activity is confirmed to be malicious, both the source and destination hosts should be considered compromised and investigated.
4.  **Review Access Controls:** Use findings to review and tighten RDP access policies. Ensure that only authorized users can initiate RDP sessions from appropriate management hosts.

---

## References

- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created hunt query to detect RDP client execution for lateral movement. |
