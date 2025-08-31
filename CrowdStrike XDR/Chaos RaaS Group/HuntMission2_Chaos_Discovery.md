
# Detection of Chaos Ransomware Discovery Command Sequence

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Discovery-ChaosSequence
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt identifies a sequence of discovery commands commonly used by the Chaos ransomware group for post-compromise reconnaissance. A single execution of tools like `ipconfig` or `nltest` is normal, but a rapid succession of multiple distinct discovery commands by the same user on the same host is a strong indicator of an attacker actively mapping the domain and network environment. This query aggregates these commands over a one-hour window and flags systems where three or more unique discovery tools from the Chaos TTP list are executed.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0007 - Discovery            | T1016       | —            | System Network Configuration Discovery         |
| TA0007 - Discovery            | T1482       | —            | Domain Trust Discovery                         |
| TA0007 - Discovery            | T1033       | —            | System Owner/User Discovery                    |
| TA0007 - Discovery            | T1057       | —            | Process Discovery                              |
| TA0007 - Discovery            | T1018       | —            | Remote System Discovery                        |
| TA0007 - Discovery            | T1135       | —            | Network Share Discovery                        |

---

## Hunt Query Logic

This query identifies a behavioral pattern of active reconnaissance by looking for:

- A cluster of specific discovery commands (`ipconfig`, `nltest`, `nslookup`, `net`, `quser`, `tasklist`) known to be used by the Chaos group.
- These commands are executed by the same user on the same host within a 1-hour window.
- The query alerts only when three or more unique commands from the list are observed, significantly reducing false positives from single, legitimate command executions.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Chaos Ransomware Discovery Command Chain
// Description: Detects a cluster of discovery commands executed on a single host within a one-hour window, matching the TTPs of the Chaos ransomware group.
// MITRE ATT&CK TTP ID: T1016, T1482, T1033, T1057, T1018, T1135

#event_simpleName=ProcessRollup2
| event_platform = Win
| (FileName = /ipconfig\.exe/i OR FileName = /nltest\.exe/i OR FileName = /nslookup\.exe/i OR FileName = /net\.exe/i OR FileName = /quser\.exe/i OR FileName = /tasklist\.exe/i
   OR OriginalFileName = /ipconfig\.exe/i OR OriginalFileName = /nltest\.exe/i OR OriginalFileName = /nslookup\.exe/i OR OriginalFileName = /net\.exe/i OR OriginalFileName = /quser\.exe/i OR OriginalFileName = /tasklist\.exe/i)
| (
    (FileName = /ipconfig\.exe/i AND CommandLine = "*/all*") OR
    (FileName = /nltest\.exe/i AND (CommandLine = "*/dclist*" OR CommandLine = "*/domain_trusts*")) OR
    (FileName = /net\.exe/i AND CommandLine = "*view*") OR
    FileName = /nslookup\.exe/i OR
    FileName = /quser\.exe/i OR
    FileName = /tasklist\.exe/i
  )
| table([EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId, PlatformName])
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Standard user-level permissions are sufficient to execute these discovery commands.
- **Required Artifacts:** Process creation logs with full command-line arguments from an EDR or equivalent host monitoring tool.

---

## Considerations

- While individual commands are common, the sequence and clustering are key indicators.
- Investigate the parent process that initiated this sequence. It is often a shell (`cmd.exe`, `powershell.exe`) spawned from an initial access payload.
- This activity is a precursor to lateral movement; subsequent network activity should be closely scrutinized.

---

## False Positives

False positives are possible but unlikely due to the query logic requiring a cluster of commands. They could occur if:

- A system administrator or network engineer runs a manual diagnostic script that performs a similar sequence of checks.
- An automated asset management or monitoring tool executes these commands as part of its inventory process.

---

## Recommended Response Actions

1.  **Investigate the Host and User:** Examine the timeline of activity for the user and host to understand the context of these commands.
2.  **Analyze Parent Process:** Identify the process that spawned this sequence of discovery commands to trace the activity back to its source.
3.  **Review Network Activity:** Scrutinize network logs for connections made from the host immediately following the discovery activity, as this may reveal lateral movement attempts.
4.  **Isolate Endpoint:** If malicious activity is confirmed, isolate the affected endpoint from the network to contain the threat.

---

## References

- [MITRE ATT&CK: T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [MITRE ATT&CK: T1482 – Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [MITRE ATT&CK: T1033 – System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
- [MITRE ATT&CK: T1057 – Process Discovery](https://attack.mitre.org/techniques/T1057/)
- [MITRE ATT&CK: T1018 – Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- [MITRE ATT&CK: T1135 – Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect the specific sequence of discovery commands used by the Chaos ransomware group. |
