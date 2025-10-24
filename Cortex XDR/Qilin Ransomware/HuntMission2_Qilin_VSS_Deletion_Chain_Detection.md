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

This XQL query processes Windows process start events and creates boolean indicators for each step of the VSS deletion chain:

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

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR / XSIAM

```xql
// Qilin Ransomware - Volume Shadow Copy Deletion Chain
// MITRE: T1490 (Inhibit System Recovery), T1569.002 (Service Execution)
// OS: Windows

config case_sensitive = false
| dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter event_type = PROCESS and event_sub_type = ENUM.PROCESS_START

// Phase 1: vssadmin.exe delete shadows
| alter vss_delete = if(
    action_process_image_name != null and action_process_image_command_line != null and
    action_process_image_name contains "vssadmin.exe" and
    action_process_image_command_line contains "delete" and
    action_process_image_command_line contains "shadow",
    1, 0
)

// Phase 2: wmic VSS service manipulation (ChangeStartMode)
| alter wmic_vss_manipulation = if(
    action_process_image_name != null and action_process_image_command_line != null and
    (action_process_image_name contains "wmic.exe" or action_process_image_name = "wmic") and
    action_process_image_command_line contains "service" and
    action_process_image_command_line contains "vss" and
    action_process_image_command_line contains "ChangeStartMode",
    1, 0
)

// Phase 3: net.exe VSS service start/stop
| alter net_vss_commands = if(
    action_process_image_name != null and action_process_image_command_line != null and
    (action_process_image_name contains "net.exe" or action_process_image_name = "net") and
    (
      (action_process_image_command_line contains "start" and action_process_image_command_line contains "vss") or
      (action_process_image_command_line contains "stop"  and action_process_image_command_line contains "vss")
    ),
    1, 0
)

// Phase 4: bcdedit boot configuration manipulation
| alter bcdedit_recovery = if(
    action_process_image_name != null and action_process_image_command_line != null and
    action_process_image_name contains "bcdedit.exe" and
    (
      (action_process_image_command_line contains "recoveryenabled"   and action_process_image_command_line contains "no") or
      (action_process_image_command_line contains "bootstatuspolicy" and action_process_image_command_line contains "ignoreallfailures")
    ),
    1, 0
)

// Aggregate by host and causality parent in 5-minute windows
| bin _time span = 5m
| comp
    sum(vss_delete) as vss_delete_count,
    sum(wmic_vss_manipulation) as wmic_count,
    sum(net_vss_commands) as net_count,
    sum(bcdedit_recovery) as bcdedit_count,
    count_distinct(action_process_image_name) as unique_tools,
    values(action_process_image_command_line) as command_samples
  by agent_hostname, _time, causality_actor_process_image_path, actor_effective_username

// Correlation: Require vssadmin deletion + at least one service manipulation
| filter vss_delete_count > 0 and (wmic_count > 0 or net_count > 0)

// Enrichment (string-only category; numeric score allowed)
| alter detection_category = "VSS Deletion Detected"
| alter detection_category = if(vss_delete_count > 0 and bcdedit_count > 0, "VSS + Boot Configuration Attack", detection_category)
| alter detection_category = if(vss_delete_count > 0 and wmic_count > 0, "VSS Deletion with Service Manipulation", detection_category)
| alter detection_category = if(vss_delete_count > 0 and wmic_count >= 2 and net_count >= 1, "Qilin VSS Deletion Chain (Full Sequence)", detection_category)

| alter risk_score = 70
| alter risk_score = if(vss_delete_count > 0, 85, risk_score)
| alter risk_score = if(vss_delete_count > 0 and (wmic_count > 0 or net_count > 0), 90, risk_score)
| alter risk_score = if(vss_delete_count > 0 and wmic_count >= 2 and net_count >= 1, 95, risk_score)
| alter risk_score = if(vss_delete_count > 0 and wmic_count >= 2 and net_count >= 1 and bcdedit_count > 0, 100, risk_score)

// Output
| fields
    agent_hostname,
    _time,
    causality_actor_process_image_path,
    actor_effective_username,
    vss_delete_count,
    wmic_count,
    net_count,
    bcdedit_count,
    unique_tools,
    command_samples,
    detection_category,
    risk_score
| sort desc risk_score, desc _time
```

---

#### Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |

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
