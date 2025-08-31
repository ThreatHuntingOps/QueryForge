# Detection of Specific Chaos RaaS Reverse SSH Tunnel Command

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Chaos-C2-ReverseSSH
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** None

---

## Hunt Analytics

This is a high-fidelity, intelligence-driven hunt query that detects the exact command-line signature used by the Chaos ransomware group to establish a command and control (C2) channel. It looks for the execution of `ssh.exe` with a specific combination of flags to create a reverse SSH tunnel: remote port forwarding (`-R`), using a non-standard port (`-p 443` to masquerade as TLS traffic), disabling host key verification, and connecting to their known C2 IP address (`45.61.134.36`). A match on this query is a definitive indicator of a compromise by this specific threat actor.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0011 - Command and Control  | T1572       | —            | Protocol Tunneling                             |
| TA0011 - Command and Control  | T1071       | .004         | Application Layer Protocol: SSH                |

---

## Hunt Query Logic

This query identifies a specific C2 channel by looking for a precise combination of elements:
- The execution of `ssh.exe`.
- The `-R` flag, indicating a reverse tunnel is being created.
- The use of port 443 (`-p 443`) for the connection.
- The hardcoded, known malicious IP address `45.61.134.36`.
- The presence of options to bypass host key checks (`StrictHostKeyChecking=no` or `UserKnownHostsFile=/dev/null`), which is common in automated malicious scripts.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Specific Chaos RaaS Reverse SSH Tunnel for C2
// Description: Detects the exact command line used by Chaos RaaS to create a reverse SSH tunnel to their C2 server over port 443, including the specific IOC IP address.
// MITRE ATT&CK TTP ID: T1572, T1071.004

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "ssh.exe" 
    and action_process_image_command_line contains "-R" 
    and action_process_image_command_line contains "-p 443" 
    and action_process_image_command_line contains "45.61.134.36" 
    and ( 
        action_process_image_command_line contains "StrictHostKeyChecking=no" 
        or action_process_image_command_line contains "UserKnownHostsFile=/dev/null" 
    ) 
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

- **Required Permissions:** Standard user-level permissions are sufficient. The `ssh.exe` client must be present on the host.
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- **Confirmed Compromise:** An alert from this query should be treated as a confirmed compromise with an active C2 channel.
- **IOC-Based:** This hunt is based on a static IP address. While highly effective, the threat actor can change their infrastructure, rendering this specific query obsolete. It should be paired with more general behavioral hunts for protocol tunneling.
- **Parent Process:** The parent process that launched this `ssh.exe` command is critical for understanding the initial infection vector.

---

## False Positives

- There are no known false positives for this query. The combination of a specific IP address known to be malicious with this exact command-line structure is unique to this threat.

---

## Recommended Response Actions

1.  **Isolate Host Immediately:** This is the highest priority. The host has an active C2 tunnel.
2.  **Block C2 IP:** Immediately block the IP address `45.61.134.36` at the network perimeter (firewall, web proxy) to sever the C2 channel.
3.  **Investigate Causality:** Identify and analyze the parent process that executed the `ssh` command to determine the root cause.
4.  **Hunt for IP:** Search all available network logs (NetFlow, DNS, proxy) across the entire environment for any other systems that have communicated with `45.61.134.36`.
5.  **Hunt for Parent Process Hash:** Take the hash of the parent process and hunt for it across the environment to find other compromised systems.

---

## References

- [MITRE ATT&CK: T1572 – Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK: T1071.004 – Application Layer Protocol: SSH](https://attack.mitre.org/techniques/T1071/004/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created high-fidelity hunt for Chaos RaaS reverse SSH tunnel command. |
