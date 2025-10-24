# Multi-Stage Qilin Ransomware Attack Chain Detection

#### Severity or Impact of the Detected Behavior
- **Risk Score:** Critical
- **Severity:** Critical

#### Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Qilin-Attack-Chain-Correlation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low

---

#### Hunt Analytics

This hunt detects the complete Qilin ransomware attack chain by correlating multiple stages of the attack within a 10-minute window on a single host. The stages include:

- **Execution:** Password-protected binary launch with `-password` argument
- **Pre-Encryption Preparation:** VSS deletion, event log clearing
- **Persistence:** Registry Run key modification with asterisk prefix
- **Impact:** QLOG folder creation, ransom note (`README-RECOVER-*.txt`) creation, and mass file encryption

The query uses string-based flags to avoid numeric operations and aggregates events by host and user within 10-minute windows. This comprehensive detection provides end-to-end visibility and is ideal for retrospective analysis after initial alerts.

---

#### ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059.001   | -            | Command and Scripting Interpreter: PowerShell |
| TA0005 - Defense Evasion     | T1140       | -            | Deobfuscate/Decode Files or Information       |
| TA0005 - Defense Evasion     | T1490       | -            | Inhibit System Recovery                       |
| TA0003 - Persistence         | T1547.001   | -            | Boot or Logon Autostart Execution: Registry Run Keys |
| TA0040 - Impact              | T1486       | -            | Data Encrypted for Impact                     |

---

#### Hunt Query Logic

This XQL query aggregates Windows process, registry, and file events within 10-minute windows to detect multiple stages of the Qilin attack chain. It uses string-based flags to indicate the presence of each stage:

- `flag_execution`: Password-protected binary launch
- `flag_vss`: VSS deletion via `vssadmin.exe`
- `flag_logclr`: Event log clearing via PowerShell
- `flag_persist`: Registry Run key modification
- `flag_qlog`: QLOG folder creation
- `flag_ransom`: Ransom note creation

The correlation logic combines these flags to identify multi-stage activity, raising confidence when multiple stages are present.

---

#### Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR / XSIAM

```xql
// Qilin Ransomware - Multi-Stage Attack Chain Correlation (string-flag, concat-safe)
// MITRE: T1059, T1070, T1547, T1490, T1486
// OS: Windows

config case_sensitive = false
| dataset = xdr_data

// Scope
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter event_type = ENUM.PROCESS or event_type = ENUM.REGISTRY or event_type = ENUM.FILE
| filter event_sub_type = ENUM.PROCESS_START or event_sub_type = ENUM.REGISTRY_SET_VALUE or event_sub_type = ENUM.FILE_DIR_CREATE

// Aggregate by host and actor within 10-minute window and produce string flags (Y or "")
| bin _time span = 10m
| comp
    max(if(event_sub_type = ENUM.PROCESS_START and action_process_image_command_line != null and action_process_image_command_line contains "-password", "Y", "")) as flag_execution,
    max(if(event_sub_type = ENUM.PROCESS_START and action_process_image_command_line != null and action_process_image_name != null and action_process_image_name contains "vssadmin.exe" and action_process_image_command_line contains "delete" and action_process_image_command_line contains "shadows", "Y", "")) as flag_vss,
    max(if(event_sub_type = ENUM.PROCESS_START and action_process_image_command_line != null and action_process_image_name != null and (action_process_image_name contains "powershell.exe" or action_process_image_name contains "pwsh.exe") and action_process_image_command_line contains "EventLogSession" and action_process_image_command_line contains "ClearLog", "Y", "")) as flag_logclr,
    max(if(event_sub_type = ENUM.REGISTRY_SET_VALUE and action_registry_key_name != null and action_registry_value_name != null and action_registry_key_name contains "CurrentVersion\\Run", "Y", "")) as flag_persist,
    max(if(event_sub_type = ENUM.FILE_DIR_CREATE and action_file_path != null and action_file_path contains "\\QLOG", "Y", "")) as flag_qlog,
    max(if(event_sub_type = ENUM.FILE_DIR_CREATE and action_file_name != null and action_file_name contains "README-RECOVER-" and action_file_name contains ".txt", "Y", "")) as flag_ransom
  by agent_hostname, _time, actor_effective_username

// Correlation / detection rules using string flags (no numeric outputs)
| alter detection_category = "Multi-Stage Ransomware Activity"
| alter detection_category = if(flag_ransom = "Y" and (flag_vss = "Y" or flag_logclr = "Y") and (flag_persist = "Y" or flag_qlog = "Y"), "Qilin Ransomware Full Attack Chain (Critical)", detection_category)
| alter detection_category = if(flag_ransom = "Y" and flag_qlog = "Y", "Qilin Encryption with QLOG Folder", detection_category)
| alter detection_category = if(flag_ransom = "Y", "Ransom Note Detected", detection_category)
| alter detection_category = if((flag_vss = "Y" and flag_logclr = "Y") and flag_persist = "Y", "Pre-Encryption with Persistence", detection_category)

// Risk label (strings only) — prioritized by combination
| alter risk_label = "Medium"
| alter risk_label = if(detection_category = "Qilin Ransomware Full Attack Chain (Critical)", "Critical", risk_label)
| alter risk_label = if(detection_category = "Qilin Encryption with QLOG Folder", "High", risk_label)
| alter risk_label = if(detection_category = "Ransom Note Detected", "High", risk_label)
| alter risk_label = if(detection_category = "Pre-Encryption with Persistence", "Elevated", risk_label)

// Attack phase (strings only)
| alter attack_phase = "Early Stage Detection"
| alter attack_phase = if(flag_ransom = "Y", "Impact (Encryption Complete)", attack_phase)
| alter attack_phase = if(flag_persist = "Y", "Persistence Established", attack_phase)
| alter attack_phase = if(flag_logclr = "Y" or flag_vss = "Y", "Pre-Encryption (Preparation)", attack_phase)

// Final output: only strings/identifiers (no numeric fields)
| fields
    agent_hostname,
    _time,
    actor_effective_username,
    detection_category,
    risk_label,
    attack_phase,
    flag_execution,
    flag_vss,
    flag_logclr,
    flag_persist,
    flag_qlog,
    flag_ransom
| sort desc _time
```

---

#### Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |
| Cortex       | xdr_data         | Registry            | Registry Modification  |
| Cortex       | xdr_data         | File                | File Creation          |

---

#### Execution Requirements

- **Required Permissions:** Collection of process, registry, and file events with full command-line, registry key, and file path details.
- **Required Artifacts:** Process start logs, registry SetValue logs, file creation logs, actor process image path, and effective username.

---

#### Considerations

- This query is designed for retrospective analysis and may not trigger in real-time. Use individual stage detections for real-time alerts.
- Correlate with network and authentication logs to identify initial compromise and lateral movement.
- Preserve affected systems for forensic analysis and avoid further writes to disk.

---

#### False Positives

False positives are extremely unlikely due to the highly specific combination of indicators across multiple attack stages.

---

#### Recommended Response Actions

1. Immediately isolate affected hosts and preserve systems for forensic analysis.
2. Notify incident response and follow organizational ransomware playbooks.
3. Collect memory dumps and file system images for analysis.
4. Query for related activity (lateral movement, privilege escalation) from the same host or user.
5. Block or quarantine binaries associated with the attack chain.
6. Begin recovery planning using backups and off-host data copies.

---

#### References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1140 – Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

---

#### Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-23 | Initial Detection | Created hunt query to detect Qilin's full attack chain across multiple stages              |
