# Volume Shadow Copy Deletion Chain

#### Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** Critical

#### Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Qilin-VSS-Deletion
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

#### Hunt Analytics

This hunt detects Qilin ransomware's multi-step Volume Shadow Copy (VSS) deletion chain. The typical sequence identified by this query includes:

- Execution of `vssadmin.exe` with commands to delete shadow copies
- Manipulation of the VSS service start mode via `wmic` (ChangeStartMode)
- Starting/stopping the VSS service via `net start` / `net stop`
- Optional boot configuration manipulations via `bcdedit` (disabling recovery or setting ignore policies)

The query aggregates process events by host and causality/actor process in 5-minute windows to correlate distinct command executions into a single multi-step chain. When vssadmin shadow deletion is observed in combination with service start/stop or ChangeStartMode operations, this is highly indicative of ransomware activity aiming to inhibit system recovery (MITRE T1490). Detection of repeated service manipulation commands, combined net + wmic usage and bcdedit changes, raises confidence to a full-sequence Qilin VSS deletion alert.

---

#### ATT&CK Mapping

| Tactic                          | Technique   | Subtechnique | Technique Name                                 |
|--------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion       | T1490       | -            | Inhibit System Recovery                       |
| TA0007 - Discovery / Execution | T1569.002   | -            | System Services: Service Execution            |

---

#### Hunt Query Logic

This query processes Windows process start events and creates boolean indicators for each step of the VSS deletion chain:

- Phase 1: detect `vssadmin.exe` invocations that include `delete` and `shadow`
- Phase 2: detect `wmic` usage targeting the `vss` service with `ChangeStartMode`
- Phase 3: detect `net start/stop vss` commands
- Phase 4: detect `bcdedit` usage that disables recovery or configures boot policies to ignore failures

Events are aggregated in 5-minute bins by host and causality actor process path so sequences executed in quick succession are correlated. The correlation filter requires at minimum a VSS deletion (`vssadmin`) plus at least one service manipulation (`wmic` or `net`) to reduce noise.

Confidence is increased when:
- Multiple wmic operations are observed alongside net commands
- bcdedit modifications are present
- Distinct tools (vssadmin, wmic, net, bcdedit) appear together (higher unique_tools count)

---

#### Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Qilin Ransomware - Volume Shadow Copy Deletion Chain (CQL) - no values()/first()
| #repo="base_sensor" event_platform="Win"

// Limit to process start events
| #event_simpleName="ProcessRollup2"

// Initialize binary flags
| vss_delete := 0
| wmic_vss_manipulation := 0
| net_vss_commands := 0
| bcdedit_recovery := 0

// Phase 1: vssadmin.exe delete shadows
| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\vssadmin\\.exe$/i or ImageFileName=/\\vssadmin$/i) and
    CommandLine=/delete/i and
    CommandLine=/shadow/i
  ) | vss_delete := 1

// Phase 2: wmic VSS service manipulation (ChangeStartMode)
| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\wmic\\.exe$/i or ImageFileName=/\\wmic$/i) and
    CommandLine=/service/i and
    CommandLine=/vss/i and
    CommandLine=/ChangeStartMode/i
  ) | wmic_vss_manipulation := 1

// Phase 3: net.exe VSS service start/stop
| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\bnet\\.exe$/i or ImageFileName=/\\bnet$/i) and
    (
      (CommandLine=/\\bstart\\b/i and CommandLine=/\\bvss\\b/i) or
      (CommandLine=/\\bstop\\b/i and CommandLine=/\\bvss\\b/i)
    )
  ) | net_vss_commands := 1

// Phase 4: bcdedit boot configuration manipulation
| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\bcdedit\\.exe$/i or ImageFileName=/\\bcdedit$/i) and
    (
      (CommandLine=/recoveryenabled\\s+no/i) or
      (CommandLine=/bootstatuspolicy/i and CommandLine=/ignoreallfailures/i)
    )
  ) | bcdedit_recovery := 1

// 5-minute aggregation window
| bin _time span = 5m

| groupBy([aid, ComputerName, causality_actor_process_image_path, UserName, _time],
    function=[
      { vss_delete_count := sum(vss_delete) },
      { wmic_count := sum(wmic_vss_manipulation) },
      { net_count := sum(net_vss_commands) },
      { bcdedit_count := sum(bcdedit_recovery) },
      { unique_tools := count(ImageFileName, distinct=true) }
    ],
    limit=max
  )

// Correlation: Require vssadmin deletion + at least one service manipulation
| vss_delete_count>0 and (wmic_count>0 or net_count>0)

// Enrichment / classification
| detection_category := "VSS Deletion Detected"
| vss_delete_count>0 and bcdedit_count>0                 | detection_category := "VSS + Boot Configuration Attack"
| vss_delete_count>0 and wmic_count>0                   | detection_category := "VSS Deletion with Service Manipulation"
| vss_delete_count>0 and wmic_count>=2 and net_count>=1 | detection_category := "Qilin VSS Deletion Chain (Full Sequence)"

// Risk scoring (numeric)
| risk_score := 70
| vss_delete_count>0                                              | risk_score := 85
| vss_delete_count>0 and (wmic_count>0 or net_count>0)           | risk_score := 90
| vss_delete_count>0 and wmic_count>=2 and net_count>=1          | risk_score := 95
| vss_delete_count>0 and wmic_count>=2 and net_count>=1 and bcdedit_count>0 | risk_score := 100

// Output
| select([
    aid,
    ComputerName,
    _time,
    causality_actor_process_image_path,
    UserName,
    vss_delete_count,
    wmic_count,
    net_count,
    bcdedit_count,
    unique_tools,
    detection_category,
    risk_score
  ])
| sort([risk_score, _time], order=desc)
```

---

#### Data Sources

| Provider                 | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component         |
|-------------------------|-----------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon      | base_sensor: ProcessRollup2 (process telemetry)          | Process            | Process Creation       |

---

#### Execution Requirements

- **Required Permissions:** Ability to execute processes on Windows endpoints and collection of process creation events with full command-line visibility.
- **Required Artifacts:** Process creation logs (command-line, image path), causality/parent process information, and event timestamps for aggregation.

---

#### Considerations

- Legitimate administrative activity (backup maintenance, snapshot pruning, or system provisioning scripts) may invoke the same commands. Validate against change windows, documented maintenance tasks, or backup/ops tickets.
- Adversaries may perform these steps quickly or intersperse them with other commands; aggregation window size (5 minutes) balances correlation vs. accidental grouping. Adjust bin size if your environment shows different timing characteristics.
- Check for related indicators of ransomware activity: mass file modification, ransom notes, unusual file extensions, spikes in file I/O, or outbound network connections to known C2.

---

#### False Positives

False positives may occur when:

- IT or backup personnel run `vssadmin`/`wmic`/`net`/`bcdedit` as part of legitimate maintenance or imaging workflows.
- Automated system management tools or third-party installers manipulate services or boot configuration.

Mitigation: Cross-reference with maintenance schedules, verify initiating user accounts, parent processes, and whether commands were executed by legitimate management tools.

---

#### Recommended Response Actions

1. Immediately review command_samples, parent process, and actor (user) context for the correlated events.
2. Query the host for additional signs of ransomware (file renames, ransom notes, rapid file encryption), and check for recent creation/deletion of shadow copies.
3. Collect volatile artifacts (process list, memory image) and preserve logs for forensic analysis.
4. If malicious, isolate the endpoint to prevent lateral movement and preserve remaining VSS snapshots if possible for recovery.
5. Notify backup administrators to ensure off-host backups remain intact and to begin recovery planning.
6. Block or quarantine offending binaries and user accounts, and strengthen detection rules to include parent-child process patterns and file system activity.

---

#### References

- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1569.002 – System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)

---

#### Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-23 | Initial Detection | Created hunt query to detect Qilin multi-step VSS deletion chain and service manipulation |
