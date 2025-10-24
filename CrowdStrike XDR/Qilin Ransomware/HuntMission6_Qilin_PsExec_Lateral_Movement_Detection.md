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

This query filters Windows process start and network events to detect PsExec-based lateral movement. It identifies PsExec execution with the `-spread` argument, outbound SMB connections, and network activity initiated by PsExec processes. The correlation logic combines multiple indicators to raise confidence.

Key points:
- Detect PsExec execution (`psexec.exe` or `psexec64.exe`)
- Detect `-spread` argument in command line
- Detect SMB connections (port 445)
- Detect PsExec network activity
- Detect parent processes with `-password` arguments

---

#### Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Qilin Ransomware - PsExec-Based Network Spreading
// MITRE: T1570, T1021.002, T1047
| #repo="base_sensor" event_platform="Win"

// Limit to process and network families we care about
| (
    #event_simpleName="ProcessRollup2" or
    #event_simpleName="NetworkConnectIP4" or
    #event_simpleName="NetworkConnectIP6"
  )

// Initialize flags (0/1)
| psexec_execution := 0
| spread_argument := 0
| smb_connection := 0
| parent_with_password := 0
| psexec_network_activity := 0

// Phase 1: PsExec execution (process start)
| (
    #event_simpleName="ProcessRollup2" and
    ImageFileName=/\\b(psexec|psexec64)\\.exe$/i
  ) | psexec_execution := 1

// Phase 2: PsExec with "-spread" argument (process start)
| (
    #event_simpleName="ProcessRollup2" and
    CommandLine=/-spread\\b/i
  ) | spread_argument := 1

// Phase 3: SMB network connections (port 445) — cover common port field names
| (
    (#event_simpleName="NetworkConnectIP4" or #event_simpleName="NetworkConnectIP6") and
    (
      RemotePort=445 or action_remote_port=445 or
      LocalPort=445  or action_local_port=445
    )
  ) | smb_connection := 1

// Phase 4: Suspicious parent process providing password argument
| (
    causality_actor_process_command_line=/-password\\b/i
  ) | parent_with_password := 1

// Phase 5: Network activity initiated by PsExec (actor process is PsExec on network events)
| (
    (#event_simpleName="NetworkConnectIP4" or #event_simpleName="NetworkConnectIP6") and
    (
      actor_process_image_name=/\\b(psexec|psexec64)\\.exe$/i or
      ActorProcessImageFileName=/\\b(psexec|psexec64)\\.exe$/i
    )
  ) | psexec_network_activity := 1

// Correlation: combine indicators into unified detection logic
| (psexec_execution=1 and smb_connection=1) or
  (spread_argument=1 and smb_connection=1) or
  (psexec_execution=1 and parent_with_password=1) or
  (psexec_network_activity=1)

// Enrichment — descriptive category labels (strings)
| detection_category := "Suspicious Lateral Movement"
| psexec_execution=1 and smb_connection=1     | detection_category := "PsExec with SMB Activity"
| spread_argument=1 and smb_connection=1     | detection_category := "Ransomware Network Spreading"
| psexec_execution=1 and spread_argument=1   | detection_category := "Qilin PsExec Spreading (High Confidence)"

// Output — safe strings/booleans only
| select([
    aid,
    ComputerName,
    _time,
    ActorProcessImageFileName,
    actor_process_image_name,
    ActorProcessCommandLine,
    CommandLine,
    ImageFileName,
    ImageFilePath,
    causality_actor_process_image_path,
    action_remote_ip,
    action_remote_port,
    action_local_port,
    RemotePort,
    LocalPort,
    psexec_execution,
    spread_argument,
    smb_connection,
    parent_with_password,
    psexec_network_activity,
    detection_category,
    #event_simpleName
  ])
| sort([_time], order=desc)
```

---

#### Data Sources

| Provider                 | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component         |
|-------------------------|-----------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon      | base_sensor: ProcessRollup2 (process telemetry)          | Process            | Process Creation       |
| CrowdStrike Falcon      | base_sensor: Network (network telemetry)                    | Network               | Network Connection    |

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
