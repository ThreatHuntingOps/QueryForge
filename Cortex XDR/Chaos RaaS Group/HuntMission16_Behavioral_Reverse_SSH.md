# Detection of Reverse SSH Tunnel with Bypassed Host Key Verification

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Behavioral-ReverseSSH
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This is a broader, behavioral hunt query designed to detect the underlying technique of using a reverse SSH tunnel while disabling security checks. This is inherently suspicious behavior, regardless of the threat actor. The query looks for `ssh.exe` creating a remote port forward (`-R`) while simultaneously using command-line options to bypass host key verification (`StrictHostKeyChecking=no` or `UserKnownHostsFile=/dev/null`). This allows for the detection of the Chaos RaaS TTP even if they change their C2 infrastructure, and it can also uncover other, unrelated malicious activity using the same technique for C2 or exfiltration.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0011 - Command and Control  | T1572       | —            | Protocol Tunneling                             |
| TA0011 - Command and Control  | T1071       | .004         | Application Layer Protocol: SSH                |
| TA0011 - Command and Control  | T1219       | —            | Remote Access Software                         |

---

## Hunt Query Logic

This query identifies a suspicious SSH tunneling technique by looking for a combination of behaviors:
- The execution of `ssh.exe`.
- The `-R` flag, indicating a reverse tunnel is being created for remote port forwarding.
- The presence of options to bypass host key checks (`StrictHostKeyChecking=no` or `UserKnownHostsFile=/dev/null`), which indicates a non-interactive, automated connection where the server's identity is not being verified.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Reverse SSH Tunnel with Bypassed Host Key Verification
// Description: Detects the creation of a reverse SSH tunnel (-R) where host key verification is explicitly disabled, a common C2 and data exfiltration technique.
// MITRE ATT&CK TTP ID: T1572, T1071.004

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "ssh.exe" 
    and action_process_image_command_line contains "-R" 
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

- **Behavioral Detection:** Unlike an IOC-based hunt, this query detects a technique, making it more resilient to changes in threat actor infrastructure.
- **Critical IOC:** The destination IP address or hostname in the command line is a critical IOC that must be extracted and investigated.
- **Parent Process:** The parent process that launched this `ssh.exe` command is key to understanding the initial point of compromise.

---

## False Positives

- False positives are low but possible. Some legitimate automated systems (e.g., CI/CD pipelines, custom data transfer scripts) may use this method for non-interactive connections. However, this is often poor security practice and should be reviewed and explicitly excluded if necessary.

---

## Recommended Response Actions

1.  **Isolate Host:** Immediately isolate the host to sever any potential C2 channel.
2.  **Identify and Block Destination:** Extract the destination IP or hostname from the command line. Investigate it and block it at the network perimeter.
3.  **Investigate Causality:** Identify and analyze the parent process that executed the `ssh` command to determine the root cause of the infection.
4.  **Hunt for Destination:** Search all available network logs (NetFlow, DNS, proxy) across the entire environment for any other systems that have communicated with the identified destination.
5.  **Hunt for Parent Process Hash:** Take the hash of the parent process and hunt for it across the environment to find other compromised systems.

---

## References

- [MITRE ATT&CK: T1572 – Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK: T1071.004 – Application Layer Protocol: SSH](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)
---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created behavioral hunt for reverse SSH tunnels with disabled security. |
