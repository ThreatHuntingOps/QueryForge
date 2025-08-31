# Suspicious DLL Execution via Msiexec Hunt Query Documentation

## Overview
This hunt query identifies executions of `msiexec.exe` that leverage the `/y` or `/z` options, which allow for the execution of DLL files. By excluding executions where the parent process is also `msiexec.exe`, this query helps surface anomalies such as DLL files located in unusual folders (e.g., temporary or user directories), which may indicate malicious activity or lateral movement.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `msiexec.exe`.
- Filters for command lines containing `/y`, `/z`, `-y`, or `-z` (case-insensitive), which are used to execute DLL files.
- Excludes events where the parent process is also `msiexec.exe` to reduce noise from legitimate chained installations.
- Surfaces suspicious DLL executions, especially those from non-standard locations.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Suspicious DLL Execution via Msiexec
#event_simpleName=ProcessRollup2 
| FileName=msiexec.exe 
| CommandLine="* /y*" or CommandLine="* /z*" or CommandLine="* -y*" or CommandLine="* -z*" 
| ParentBaseFileName!=msiexec.exe
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Falcon       | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process execution events from Windows endpoints.
- **Required Artifacts:** Process execution logs, command line arguments, parent/child process relationships.

---

## Considerations

- Investigate DLL files executed via `msiexec.exe`, especially those located in temporary, user, or other non-standard directories.
- Review the parent process and user context for additional signs of compromise.
- Correlate with other suspicious behaviors, such as network connections or file writes.

---

## False Positives

False positives may occur if:
- Legitimate software deployment tools use `/y` or `/z` options for DLL execution.
- Internal IT automation scripts invoke `msiexec.exe` with these options for valid reasons.

---

## Recommended Response Actions

1. Investigate the DLL file path and its source.
2. Validate the legitimacy of the DLL and its signature.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1218.007 – Msiexec](https://attack.mitre.org/techniques/T1218/007/)
- [LOLBAS: Msiexec](https://lolbas-project.github.io/lolbas/Binaries/Msiexec/)
- [CrowdStrike: Detecting Malicious Msiexec Usage](https://www.crowdstrike.com/blog/detecting-malicious-msiexec-usage/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect suspicious DLL execution via msiexec                           |
