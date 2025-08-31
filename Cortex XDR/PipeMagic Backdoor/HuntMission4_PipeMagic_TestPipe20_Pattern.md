# Detection of PipeMagic Loader Using Named Pipe "test_pipe20.%d" Pattern

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-PipeMagic-TestPipe20-Pattern
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics
This hunt identifies processes consistent with the PipeMagic loader that create or use named pipes formatted as `\\.\pipe\test_pipe20.%d` (where `%d` is typically the target process ID). The loader continuously reads/writes on this pipe to drive a command handler loop. This detection focuses on surface indicators available in EDR telemetry: command-line references to the pipe name and nearby local loopback C2 behavior previously associated with PipeMagic (`127.0.0.1:8082`).

Detected behaviors include:
- Process starts where the command line includes `\\.\pipe\test_pipe20.` (unique per PID pattern)
- Optional correlation with local loopback network connections to `127.0.0.1:8082` characteristic of PipeMagic infrastructure

These techniques are associated with covert inter-process communication, command handling loops, and local proxy C2 channels.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                   |
|------------------------------|-------------|--------------|--------------------------------------------------|
| TA0011 - Command and Control | T1106       | —            | Native API                                       |
| TA0011 - Command and Control | T1090.001   | —            | Proxy: Internal Proxy                            |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                                |
| TA0010 - Exfiltration        | T1041       | —            | Exfiltration Over C2 Channel                     |

Notes:
- T1106 aligns with named pipe creation and manipulation via Windows APIs.
- T1090.001 corresponds to the loopback proxy behavior at `127.0.0.1:8082`.
- T1055/T1041 are commonly observed in similar backdoors for memory staging and data exfiltration over established channels.

---

## Hunt Query Logic
This hunt provides a focused query that detects command-line references to the specific `test_pipe20.` pattern used by PipeMagic loaders. The pattern `\\.\pipe\test_pipe20.%d` where `%d` represents a process ID is highly specific to this malware family and rarely appears in legitimate software.

Analysts should correlate detections with:
- Local loopback connections to `127.0.0.1:8082`
- Process lineage and parent/child relationships
- File hashes and digital signatures
- Timing proximity of related events

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: PipeMagic Loader - test_pipe20 Pipe String in Command Line
// Description: Finds Windows process starts where the command line includes \\.\pipe\test_pipe20. (unique per PID).
// MITRE ATT&CK TTP ID: T1106
// MITRE ATT&CK TTP ID: T1090.001 (see Query B)

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
  and event_sub_type = ENUM.PROCESS_START 
  and agent_os_type = ENUM.AGENT_OS_WINDOWS 
  and action_process_image_command_line contains "\\.\pipe\test_pipe20." 
| fields _time, agent_hostname, actor_effective_username, 
         action_process_image_name, action_process_image_path, action_process_image_command_line, 
         action_process_image_sha256, action_file_md5, 
         actor_process_image_name, actor_process_image_path, actor_process_command_line, 
         event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Collection of Windows process creation telemetry with full command-line arguments.
- **Required Artifacts:** Process events with complete command-line strings, file hashes, and process lineage data.

---

## Considerations
- The `test_pipe20.` pattern is highly specific to PipeMagic and should generate minimal false positives.
- Consider correlating with network telemetry showing `127.0.0.1:8082` connections within a tight time window.
- Monitor for subsequent process injection, memory manipulation, or additional named pipe creation.
- The numeric suffix typically corresponds to a target process ID; analyze the full pipe name for context.
- Review parent processes and execution context to identify initial infection vectors.

---

## False Positives
- Legitimate software rarely uses the specific `test_pipe20.` naming convention.
- Developer testing or debugging tools might create similar patterns but should be easily distinguished by context and digital signatures.

---

## Recommended Response Actions
1. Investigate the process creating or referencing the `test_pipe20.` pipe, including parent process lineage.
2. Correlate with local loopback network connections to `127.0.0.1:8082` on the same host.
3. Collect volatile artifacts: running processes, open handles/pipes, listening ports, and memory dumps if feasible.
4. Contain affected endpoints if PipeMagic behavior is confirmed.
5. Hunt for persistence mechanisms (services, scheduled tasks, registry modifications).
6. Block or monitor processes exhibiting this pipe pattern; restrict loopback port 8082 if not legitimately used.

---

## References
- MITRE ATT&CK: T1106 – Native API https://attack.mitre.org/techniques/T1106/
- MITRE ATT&CK: T1090.001 – Proxy: Internal Proxy https://attack.mitre.org/techniques/T1090/001/
- MITRE ATT&CK: T1055 – Process Injection https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel https://attack.mitre.org/techniques/T1041/

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-22 | Initial Detection | Hunt for PipeMagic loader using test_pipe20.%d named pipe pattern in command lines. |
