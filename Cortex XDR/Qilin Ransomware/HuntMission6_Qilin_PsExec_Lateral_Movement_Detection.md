# PsExec-Based Network Spreading

#### Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

#### Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Qilin-PsExec-Lateral-Movement
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

#### Hunt Analytics

This hunt detects Qilin ransomware's lateral movement capability using PsExec with the `-spread` argument. The query correlates PsExec execution with outbound SMB connections (port 445) and remote process creation events. This multi-phase detection identifies both the tool usage and network propagation patterns, indicating active lateral spread.

Detected behaviors include:

- Execution of `psexec.exe` or `psexec64.exe` with the `-spread` argument (Qilin-specific)
- Outbound SMB connections (TCP port 445) from hosts where PsExec was executed
- PsExec network activity (any outbound connection made by PsExec process)
- Parent processes with `-password` arguments (indicating credential use for lateral execution)

This behavior is highly indicative of Qilin ransomware spreading across the network using PsExec as a deployment mechanism.

---

#### ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement     | T1570      | -            | Lateral Tool Transfer                         |
| TA0008 - Lateral Movement    | T1021.002   | -            | Remote Services: SMB/Windows Admin Shares     |
| TA0002 - Execution           | T1047       | -            | Windows Management Instrumentation (WMI)     |

---

#### Hunt Query Logic

This XQL query filters Windows process start and network events to detect PsExec-based lateral movement. It identifies PsExec execution with the `-spread` argument, outbound SMB connections, and network activity initiated by PsExec processes. The correlation logic combines multiple indicators to raise confidence.

Key points:
- Detect PsExec execution (`psexec.exe` or `psexec64.exe`)
- Detect `-spread` argument in command line
- Detect SMB connections (port 445)
- Detect PsExec network activity
- Detect parent processes with `-password` arguments

---

#### Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR / XSIAM

```xql
// Qilin Ransomware - PsExec-Based Network Spreading
// MITRE: T1570 (Lateral Tool Transfer), T1021.002 (Remote Services: SMB/Admin Shares), T1047 (WMI)
// OS: Windows

config case_sensitive = false
| dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter event_type = ENUM.PROCESS or event_type = ENUM.NETWORK
| filter event_sub_type = ENUM.PROCESS_START

// Phase 1: Detect PsExec execution
// Identify when PsExec or PsExec64 was launched on the host
| alter psexec_execution = if(
    event_sub_type = ENUM.PROCESS_START and
    action_process_image_name != null and
    (action_process_image_name contains "psexec.exe" or action_process_image_name contains "psexec64.exe"),
    true, false
)

// Phase 2: Detect PsExec execution with the "--spread" argument (Qilin’s lateral feature)
| alter spread_argument = if(
    event_sub_type = ENUM.PROCESS_START and
    action_process_image_command_line != null and
    action_process_image_command_line contains "-spread",
    true, false
)

// Phase 3: Detect SMB network connections (TCP port 445)
// PsExec and related tools commonly use SMB for remote deployment and execution
| alter smb_connection = if(
    event_type = ENUM.NETWORK and
    (action_remote_port = 445 or action_local_port = 445),
    true, false
)

// Phase 4: Detect suspicious parent process with password argument
// Indicates the operator providing credentials for lateral execution
| alter parent_with_password = if(
    causality_actor_process_command_line != null and
    causality_actor_process_command_line contains "-password",
    true, false
)

// Phase 5: Detect network connections initiated by PsExec itself
// Any outbound connection made by a PsExec process
| alter psexec_network_activity = if(
    event_type = ENUM.NETWORK and
    actor_process_image_name != null and
    (actor_process_image_name contains "psexec.exe" or actor_process_image_name contains "psexec64.exe"),
    true, false
)

// Phase 6: Correlation filter — combine multiple PsExec indicators into unified detection logic
| filter (psexec_execution = true and smb_connection = true) or
         (spread_argument = true and smb_connection = true) or
         (psexec_execution = true and parent_with_password = true) or
         (psexec_network_activity = true)

// Phase 7: Enrichment — assign descriptive category labels (string‑only)
// Create a contextual label showing what combination of behaviors was found
| alter detection_category = "Suspicious Lateral Movement"
| alter detection_category = if(psexec_execution = true and smb_connection = true,       "PsExec with SMB Activity", detection_category)
| alter detection_category = if(spread_argument = true and smb_connection = true,       "Ransomware Network Spreading", detection_category)
| alter detection_category = if(psexec_execution = true and spread_argument = true,     "Qilin PsExec Spreading (High Confidence)", detection_category)

// Phase 8: Output — only safe strings and booleans, no numerics
| fields
    agent_hostname,
    _time,
    actor_process_image_name,
    actor_process_command_line,
    action_process_image_name,
    action_process_image_command_line,
    causality_actor_process_image_path,
    action_remote_ip,
    action_remote_port,
    action_local_port,
    psexec_execution,
    spread_argument,
    smb_connection,
    parent_with_password,
    psexec_network_activity,
    detection_category
| sort desc _time
```

---

#### Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |
| Cortex       | xdr_data         | Network             | Network Connection     |

---

#### Execution Requirements

- **Required Permissions:** Collection of process creation and network connection events with full command-line and network details.
- **Required Artifacts:** Process start logs, network connection logs, actor process image path, and effective username.

---

#### Considerations

- Legitimate use of PsExec by administrators may trigger this detection. Validate against change control records and user context.
- Correlate with other Qilin indicators (VSS deletion, event log clearing, registry persistence) to confirm compromise.
- Monitor for additional lateral movement techniques (e.g., WMI, PowerShell remoting) if PsExec is blocked or detected.

---

#### False Positives

False positives may occur when:

- IT administrators use PsExec for legitimate remote administration tasks.
- Automated deployment tools use PsExec for software distribution.

Mitigation: Cross-reference with maintenance schedules, validate initiating user accounts, and check for related suspicious activity.

---

#### Recommended Response Actions

1. Review PsExec execution events for suspicious actor context, command-line arguments, and network connections.
2. Query for related activity (file encryption, ransom notes, lateral movement) from the same host or user.
3. Collect forensic artifacts and isolate affected hosts if malicious activity is confirmed.
4. Notify incident response and follow organizational ransomware playbooks.
5. Block or quarantine binaries associated with suspicious PsExec usage.
6. Implement network segmentation and restrict SMB access to reduce lateral movement risk.

---

#### References

- [MITRE ATT&CK: T1570 – Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)

---

#### Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-23 | Initial Detection | Created hunt query to detect Qilin's PsExec-based network spreading with `-spread` argument |
