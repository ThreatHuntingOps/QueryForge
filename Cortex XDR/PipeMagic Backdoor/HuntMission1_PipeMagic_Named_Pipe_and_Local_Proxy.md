# Detection of PipeMagic Named Pipe Pattern with Local 127.0.0.1:8082 Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-PipeMagic-NamedPipe-LocalProxy
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low–Medium

---

## Hunt Analytics
This hunt detects the characteristic interprocess communication and local proxy behavior of the PipeMagic backdoor. PipeMagic creates named pipes with a specific format (\\.\pipe\1.) using a random 16-byte array or a magic string (`magic3301`) and communicates over those pipes to transmit encrypted payloads and notifications. Concurrently, the backdoor maintains a loopback network interface on `127.0.0.1:8082` that can be correlated with the named pipe activity.

Detected behaviors include:
- Process starts where the command line indicates PipeMagic pipe usage: `\\.\pipe\1.` or `\\.\pipe\magic3301`
- Local loopback network connections to `127.0.0.1:8082` on Windows endpoints

These techniques are associated with covert C2, data staging/exfiltration over local channels, and defense evasion.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                   |
|------------------------------|-------------|--------------|--------------------------------------------------|
| TA0011 - Command and Control | T1090.001   | —            | Proxy: Internal Proxy                            |
| TA0011 - Command and Control | T1106       | —            | Native API                                       |
| TA0005 - Defense Evasion     | T1036.005   | —            | Masquerading: Match Legitimate Name or Location  |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                                |
| TA0010 - Exfiltration        | T1041       | —            | Exfiltration Over C2 Channel                     |

Notes:
- T1106 and T1036.005 align with the named pipe creation and potential masquerading in command lines.
- T1090.001 aligns with the loopback proxy behavior at `127.0.0.1:8082`.
- T1055/T1041 are commonly observed in similar backdoors for in-memory staging and exfiltration over established channels.

---

## Hunt Query Logic
This hunt provides two complementary queries that can be executed independently or correlated:
- Query 1 identifies suspicious command lines referencing PipeMagic-style named pipes (`\\.\pipe\1.` and `\\.\pipe\magic3301`).
- Query 2 identifies local loopback network connections to `127.0.0.1:8082` indicative of the PipeMagic local interface.

Analysts can manually correlate by hostname, user, process lineage, timestamps, and actor process details. Add allowlists or additional filters (e.g., specific image names or hashes) to reduce noise in your environment.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: PipeMagic Pipe String in Process Command Line
// Description: Finds Windows process starts where the command line suggests PipeMagic pipes (randomized or magic3301 string).
// MITRE ATT&CK TTP ID: T1106 (Native API) / T1056 (for pipe usage context) / T1036.005 (Masquerading)

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
  and event_sub_type = ENUM.PROCESS_START 
  and agent_os_type = ENUM.AGENT_OS_WINDOWS 
  and ( 
       action_process_image_command_line contains "\\.\pipe\1." 
    or action_process_image_command_line contains "\\.\pipe\magic3301" 
  ) 
| fields _time, agent_hostname, actor_effective_username, 
         action_process_image_name, action_process_image_path, action_process_image_command_line, 
         action_process_image_sha256, action_file_md5, 
         actor_process_image_name, actor_process_image_path, actor_process_command_line, 
         event_id, agent_id, _product 
| sort desc _time
```

```xql
// Title: PipeMagic Local Network Activity Detection
// Description: Detects network connections to 127.0.0.1:8082 which is characteristic of PipeMagic backdoor
// MITRE ATT&CK TTP ID: T1090.001

config case_sensitive = false  
| dataset = xdr_data  
| filter event_type = ENUM.NETWORK  
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_remote_ip = "127.0.0.1" 
    and action_local_port = 8082 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_local_ip, action_local_port, action_remote_ip, action_remote_port, causality_actor_process_command_line, causality_actor_primary_username, event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |
| Cortex XSIAM | xdr_data   | Network Traffic    | Connection            |

---

## Execution Requirements
- **Required Permissions:** Ability to collect Windows process creation and network telemetry from endpoints.
- **Required Artifacts:** Process creation logs with full command lines; network connection logs including local/remote IPs and ports; process lineage/causality data for correlation.

---

## Considerations
- The pipe string `\\.\pipe\1.` may be followed by randomized 16-byte values; substring detection on `\\.\pipe\1.` is used to catch variants.
- Consider environment-specific named pipes that may incidentally include similar patterns; tune with allowlists if needed.
- Correlate named pipe detections with local `127.0.0.1:8082` activity within a tight time window on the same host.
- Enhance fidelity by adding filters such as `action_process_image_name = "chatgpt.exe"` or known malicious hashes (`action_file_md5`, `action_process_image_sha256`).
- Review parent/child process relationships to identify initial loaders or droppers.

---

## False Positives
- Some legitimate software uses named pipes and local loopback communication. However, the specific combination of `\\.\pipe\1.` or `\\.\pipe\magic3301` and `127.0.0.1:8082` is uncommon.
- Admin tools, debuggers, or developer utilities could momentarily open loopback ports; verify context and frequency.

---

## Recommended Response Actions
1. Triage detections by host and user; correlate command line and loopback events.
2. Acquire volatile artifacts: running processes, open handles/pipes, listening ports, and memory if feasible.
3. Contain affected endpoints if backdoor behavior is confirmed.
4. Block or monitor processes that spawn with suspicious pipe patterns; restrict loopback port 8082 if not used legitimately.
5. Hunt for lateral movement or additional persistence (e.g., services, scheduled tasks).
6. Update detection content with observed unique pipe suffixes and hashes.

---

## References
- MITRE ATT&CK: T1090.001 – Proxy: Internal Proxy https://attack.mitre.org/techniques/T1090/001/
- MITRE ATT&CK: T1106 – Native API https://attack.mitre.org/techniques/T1106/
- MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location https://attack.mitre.org/techniques/T1036/005/
- MITRE ATT&CK: T1055 – Process Injection https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel https://attack.mitre.org/techniques/T1041/

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-22 | Initial Detection | Created PipeMagic named pipe and local proxy hunt for XSIAM, including alternative network correlation query. |
