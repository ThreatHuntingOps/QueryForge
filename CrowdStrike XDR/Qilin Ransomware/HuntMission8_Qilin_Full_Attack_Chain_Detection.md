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

This query aggregates Windows process, registry, and file events within 10-minute windows to detect multiple stages of the Qilin attack chain. It uses string-based flags to indicate the presence of each stage:

- `flag_execution`: Password-protected binary launch
- `flag_vss`: VSS deletion via `vssadmin.exe`
- `flag_logclr`: Event log clearing via PowerShell
- `flag_persist`: Registry Run key modification
- `flag_qlog`: QLOG folder creation
- `flag_ransom`: Ransom note creation

The correlation logic combines these flags to identify multi-stage activity, raising confidence when multiple stages are present.

---

#### Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Qilin Ransomware - Multi-Stage Attack Chain Correlation (string-flag, concat-safe)
// MITRE: T1059, T1070, T1547, T1490, T1486
| #repo="base_sensor" event_platform="Win"

// Scope: process start, registry set, dir create, and file write families
| (
    #event_simpleName="ProcessRollup2" or
    #event_simpleName="RegistrySetValue" or
    #event_simpleName="FileDirCreate" or
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="FileRename" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten"
  )

// Per-event integer markers
| flag_execution_int := 0
| flag_vss_int := 0
| flag_logclr_int := 0
| flag_persist_int := 0
| flag_qlog_int := 0
| flag_ransom_int := 0

// Password-protected execution
| (#event_simpleName="ProcessRollup2" and CommandLine=/-password\b/i)                       | flag_execution_int := 1

// vssadmin delete shadows
| (#event_simpleName="ProcessRollup2" and ImageFileName=/\\bvssadmin\\.exe$/i and CommandLine=/delete/i and CommandLine=/shadows/i)
                                                                                             | flag_vss_int := 1

// PowerShell EventLogSession + ClearLog
| (#event_simpleName="ProcessRollup2" and (ImageFileName=/\\bpowershell\\.exe$/i or ImageFileName=/\\bpwsh\\.exe$/i) and CommandLine=/EventLogSession/i and CommandLine=/ClearLog/i)
                                                                                             | flag_logclr_int := 1

// Persistence via Run key modification (registry set)
| (#event_simpleName="RegistrySetValue" and RegistryKeyPath=/CurrentVersion\\Run/i)            | flag_persist_int := 1

// QLOG folder creation or path contains \QLOG
| ((#event_simpleName="FileDirCreate" or #event_simpleName="NewFileWritten" or #event_simpleName="FileWritten") and (FilePath=/\\QLOG/i or TargetFilePath=/\\QLOG/i or FilePath=/\\Temp\\QLOG/i or TargetFilePath=/\\Temp\\QLOG/i))
                                                                                             | flag_qlog_int := 1

// Ransom README creation
| ((#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and FileName=/^README-RECOVER-.*\.txt$/i)
                                                                                             | flag_ransom_int := 1

// Aggregate by host + user in 10-minute windows
| bin _time span = 10m

| groupBy([aid, ComputerName, UserName, _time],
    function=[
      { flag_execution_count := sum(flag_execution_int) },
      { flag_vss_count := sum(flag_vss_int) },
      { flag_logclr_count := sum(flag_logclr_int) },
      { flag_persist_count := sum(flag_persist_int) },
      { flag_qlog_count := sum(flag_qlog_int) },
      { flag_ransom_count := sum(flag_ransom_int) }
    ],
    limit=max
  )

// Convert counts to string flags using conditional assignment (avoids inline if(...))
| flag_execution := ""
| flag_execution_count>0 | flag_execution := "Y"

| flag_vss := ""
| flag_vss_count>0 | flag_vss := "Y"

| flag_logclr := ""
| flag_logclr_count>0 | flag_logclr := "Y"

| flag_persist := ""
| flag_persist_count>0 | flag_persist := "Y"

| flag_qlog := ""
| flag_qlog_count>0 | flag_qlog := "Y"

| flag_ransom := ""
| flag_ransom_count>0 | flag_ransom := "Y"

// Classification using pipe-assignment style
| detection_category := "Multi-Stage Ransomware Activity"
| flag_ransom="Y" and (flag_vss="Y" or flag_logclr="Y") and (flag_persist="Y" or flag_qlog="Y") | detection_category := "Qilin Ransomware Full Attack Chain (Critical)"
| flag_ransom="Y" and flag_qlog="Y"                                                              | detection_category := "Qilin Encryption with QLOG Folder"
| flag_ransom="Y"                                                                                | detection_category := "Ransom Note Detected"
| (flag_vss="Y" and flag_logclr="Y") and flag_persist="Y"                                        | detection_category := "Pre-Encryption with Persistence"

// Risk label (strings only)
| risk_label := "Medium"
| detection_category="Qilin Ransomware Full Attack Chain (Critical)" | risk_label := "Critical"
| detection_category="Qilin Encryption with QLOG Folder"             | risk_label := "High"
| detection_category="Ransom Note Detected"                         | risk_label := "High"
| detection_category="Pre-Encryption with Persistence"              | risk_label := "Elevated"

// Attack phase (strings only)
| attack_phase := "Early Stage Detection"
| flag_persist="Y" | attack_phase := "Persistence Established"
| flag_logclr="Y" or flag_vss="Y" | attack_phase := "Pre-Encryption (Preparation)"
| flag_ransom="Y" | attack_phase := "Impact (Encryption Complete)"

// Final output (strings/identifiers only)
| select([
    aid,
    ComputerName,
    _time,
    UserName,
    detection_category,
    risk_label,
    attack_phase,
    flag_execution,
    flag_vss,
    flag_logclr,
    flag_persist,
    flag_qlog,
    flag_ransom
  ])
| sort([_time], order=desc)
```

---

#### Data Sources

| Provider                 | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component         |
|-------------------------|-----------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon      | base_sensor: ProcessRollup2 (process telemetry)          | Process            | Process Creation       |
| CrowdStrike Falcon      | base_sensor: NewFileWritten/FileWritten (file telemetry) | File               | File Creation/Write    |

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
