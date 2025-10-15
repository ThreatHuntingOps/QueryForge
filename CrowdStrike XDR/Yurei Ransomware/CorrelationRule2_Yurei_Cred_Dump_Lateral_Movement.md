# Credential Dumping Followed by Lateral Movement (Correlation Rule)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100 (Credential dumping + ≥2 remote hosts + remote exec/file drop within 15 min)
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-CredDump-LateralMovement
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium (tunable with admin allowlists)
- **Lookback/Temporal Window:** 15 minutes (same source host)
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Analytics

This correlation rule detects the sequence of credential theft followed by lateral movement and remote execution using CrowdStrike Falcon telemetry.

Phases on the same source host within 15 minutes:
- **Phase 1 - Credential Access (T1003):** Execution of credential dumping tools or LSASS credential access patterns.
- **Phase 2 - Lateral Movement (T1021.002/T1059.001):** Remote authentication to multiple hosts (e.g., SMB/135/RDP).
- **Phase 3 - Remote Execution/Transfer (T1047/T1059.001/T1570):** PowerShell CIM/WMI remote execution or executable file drops to UNC paths.

Requiring all three phases increases fidelity and ties credential access to immediate lateral actions.

---

## ATT&CK Mapping

| Tactic            | Technique | Subtechnique | Technique Name                                 |
|-------------------|----------:|-------------:|------------------------------------------------|
| Credential Access | T1003     | -            | OS Credential Dumping                           |
| Lateral Movement  | T1021     | .002         | Remote Services: SMB/Windows Admin Shares       |
| Execution         | T1047     | -            | Windows Management Instrumentation               |
| Execution         | T1059     | .001         | PowerShell                                      |

---

## Correlation Logic

- Scope: Same source host (aid, ComputerName) and user context (UserName)
- Window: 15 minutes
- Thresholds:
  - Phase 1: ≥1 credential dumping event
  - Phase 2: Remote auth to ≥2 distinct remote hosts (IPv4/IPv6 combined)
  - Phase 3: ≥1 remote execution event OR ≥1 executable file drop to UNC share

---

## Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Correlation Rule: Credential Theft + Lateral Movement Detected
// Phases: Cred Dump (T1003) → Remote Auth (T1021.002) → Remote Exec/File Drop (T1047/T1059.001/T1570)

| #repo="base_sensor" event_platform="Win"

// Limit to required event families (process, network, file writes)
| (
    #event_simpleName="ProcessRollup2" or
    #event_simpleName="NetworkConnectIP4" or
    #event_simpleName="NetworkConnectIP6" or
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten"
  )

// Initialize phase flags
| phase1_cred_dump := 0
| phase2_remote_auth := 0
| phase3_remote_exec := 0
| phase3_file_drop := 0

// Phase 1: Credential dumping (mimikatz/procdump, sekurlsa, reg save sam)
| (
    #event_simpleName="ProcessRollup2" and
    (
    ImageFileName=/\\(mimikatz\\.exe|procdump\\.exe|procdump64\\.exe)$/i or
    CommandLine=/sekurlsa::logonpasswords/i or
    (ImageFileName=/\\reg\\.exe$/i and CommandLine=/save\\s+hklm\\s*\\\\?sam/i)
    )
  ) | phase1_cred_dump := 1

// Phase 2: Remote authentication (network connections to SMB/RPC/RDP)
| (
    (#event_simpleName="NetworkConnectIP4" or #event_simpleName="NetworkConnectIP6") and
    (RemotePort=445 or RemotePort=135 or RemotePort=3389) and
    (RemoteAddressIP4=* or RemoteAddressIP6=*)
  ) | phase2_remote_auth := 1

// Phase 3a: Remote execution via PowerShell CIM/WMI
| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and
    (CommandLine=/\\bNew-CimSession\\b/i or CommandLine=/\\bInvoke-CimMethod\\b/i)
  ) | phase3_remote_exec := 1

// Phase 3b: Executable file drops to UNC network shares
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    TargetFileName=/^\\\\[^\\]+\\/i and
    FileName=/\\.exe$/i
  ) | phase3_file_drop := 1

// Keep only rows that touch at least one phase
| (phase1_cred_dump=1 or phase2_remote_auth=1 or phase3_remote_exec=1 or phase3_file_drop=1)

// Aggregate by source host and user context across the query time window
| groupBy([aid, ComputerName, UserName],
    function=[
    { cred_dump_count := sum(phase1_cred_dump) },
    { unique_remote_hosts := count(RemoteAddressIP4, distinct=true) },
    { unique_remote_hosts_v6 := count(RemoteAddressIP6, distinct=true) },
    { remote_exec_count := sum(phase3_remote_exec) },
    { file_drop_count := sum(phase3_file_drop) }
    ],
    limit=max
)

// Combine v4 + v6 distinct counts (post-aggregation arithmetic only)
| total_unique_remote_hosts := unique_remote_hosts + unique_remote_hosts_v6

// Correlation condition: Cred dump present, ≥2 unique remote hosts, and (remote exec OR file drop)
| cred_dump_count>0
| total_unique_remote_hosts>=2
| (remote_exec_count>0 or file_drop_count>0)

// Enrichment
| alert_severity := "CRITICAL"
| alert_name := "Credential Theft + Lateral Movement Detected"
| confidence := "HIGH"
| recommended_action := "IMMEDIATE RESPONSE: Isolate source host, reset credentials, investigate remote hosts"
| mitre_techniques := "T1003, T1021.002, T1047, T1059.001, T1570"

// Output
| select([
    aid,
    ComputerName,
    UserName,
    cred_dump_count,
    total_unique_remote_hosts,
    remote_exec_count,
    file_drop_count,
    alert_severity,
    alert_name,
    confidence,
    recommended_action,
    mitre_techniques
])
| sort([total_unique_remote_hosts], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                                          | ATT&CK Data Source | Data Component                   |
|--------------------|-------------------------------------------------------------------|--------------------|----------------------------------|
| CrowdStrike Falcon | base_sensor: ProcessRollup2 (process telemetry)                   | Process            | Process Creation                 |
| CrowdStrike Falcon | base_sensor: NetworkConnectIP4/NetworkConnectIP6 (network flows) | Network            | Network Connection               |
| CrowdStrike Falcon | base_sensor: NewFileWritten/FileWritten (file telemetry)         | File               | File Write / File Creation       |

Field notes:
- Host identity: aid (Agent ID), ComputerName; user context: UserName
- Process fields: ImageFileName, CommandLine; Network fields: RemotePort, RemoteAddressIP4/IPv6
- File fields: FileName, TargetFileName; Event selector: #event_simpleName

---

## Execution Requirements
- **Required Permissions:** Local admin often required for dumping credentials; network access for SMB/RPC/RDP; PowerShell remoting permissions for CIM/WMI.
- **Required Artifacts:** Process, network, and file telemetry; command-line parameters; remote IP/port fields.

---

## Rationale for Fidelity
- **Attack Lifecycle Chaining:** Ties credential access to subsequent lateral actions.
- **Multiple Host Requirement:** ≥2 remote hosts reduces noise from single-host admin tasks.
- **Tight Temporal Window:** 15-minute window correlates related activity bursts.
- **User Context:** Uses UserName (Falcon) to pinpoint compromised accounts.

---

## Potential Bypasses/Limitations
- **Slow and Low:** Attacks stretched beyond 15 minutes may evade correlation.
- **Fileless Lateral Movement:** If only WMI/CIM is used without file drops, detection still triggers via Phase 3a; other remoting methods may be missed.
- **Legitimate Admin Activity:** IT operations may resemble this behavior; tune with allowlists and PAW accounts.

### Mitigation
- Extend window to 30–60 minutes for slower campaigns.
- Allowlists for known admin accounts, jump boxes/PAWs, and maintenance windows.
- Increase unique_remote_hosts threshold (e.g., 3–5) in large enterprises.

---

## Recommended Response Actions
1. Isolate the source host (Falcon Host containment) and suspend network access.
2. Reset credentials for involved user accounts; invalidate tokens/refresh sessions.
3. Investigate all remote hosts accessed during the window for execution artifacts.
4. Acquire volatile data (memory, handle lists) and relevant Falcon logs from source and targets.
5. Block further remoting from the source via firewall/EDR controls.
6. Hunt for additional credential access tools and LSASS access attempts.
7. Review lateral movement pathways (SMB drops, WMI/CIM execution) and close gaps.
8. Engage IR and follow lateral movement containment procedures; consider Falcon OverWatch escalation.

---

## References
- [MITRE ATT&CK: T1003 – OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK: T1021.002 – SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

## Version History

| Version | Date       | Impact                 | Notes                                                      |
|---------|------------|------------------------|------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Correlation    | Credential dumping followed by lateral movement detection  |
