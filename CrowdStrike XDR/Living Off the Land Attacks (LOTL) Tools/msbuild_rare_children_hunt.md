# Rare MSBuild Children Hunt Query Documentation

## Overview
This hunt query identifies rare or unusual child processes spawned by `msbuild.exe`. Adversaries may abuse MSBuild to execute malicious payloads or scripts, and the presence of unexpected child processes can be a strong indicator of suspicious or malicious activity.

---

## Hunt Query Logic

- Retrieves all process execution events where the parent process is `msbuild.exe`.
- Excludes events where the child process is also `msbuild.exe` (to focus on non-standard children).
- Surfaces rare or unexpected child processes for further investigation.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Rare MSBuild Children 
#event_simpleName=ProcessRollup2 
| ParentBaseFileName=msbuild.exe 
| FileName!=msbuild.exe
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Falcon       | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process execution events from Windows endpoints.
- **Required Artifacts:** Process execution logs, parent/child process relationships.

---

## Considerations

- Investigate any non-standard child process spawned by `msbuild.exe`.
- Review the command line and context of the child process for signs of malicious activity.
- Correlate with other suspicious behaviors, such as file writes or network connections.

---

## False Positives

False positives may occur if:
- Legitimate build or deployment tools invoke child processes from `msbuild.exe`.
- Internal automation scripts use MSBuild for valid purposes.

---

## Recommended Response Actions

1. Investigate the child process and its command line.
2. Validate the legitimacy of the child process and its source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1127 – MSBuild](https://attack.mitre.org/techniques/T1127/)
- [LOLBAS: MSBuild](https://lolbas-project.github.io/lolbas/Binaries/MSBuild/)
- [CrowdStrike: Detecting Malicious MSBuild Usage](https://www.crowdstrike.com/blog/detecting-malicious-msbuild-usage/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect rare msbuild child processes                                  |
