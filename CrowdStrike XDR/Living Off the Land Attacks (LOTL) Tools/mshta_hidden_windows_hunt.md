# Hidden Mshta Windows Hunt Query Documentation

## Overview
This hunt query identifies attempts to hide the execution of `mshta.exe` by leveraging the `resizeTo` or `moveTo` JavaScript functions. Adversaries may use these functions with single-digit values to make a window very small or with negative values to move the window off screen, thereby evading user detection and security controls.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `mshta.exe`.
- Filters for command lines containing `resizeTo` or `moveTo`.
- Extracts the transition type and values from the command line using regex for further analysis.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Hidden Mshta Windows 
#event_simpleName=ProcessRollup2 
| FileName=mshta.exe 
| CommandLine="*resizeto*" or CommandLine="*moveto*" 
| rex field=CommandLine "(?i)(?<TransitionType>resizeTo|moveTo)\\((?<TransitionValue>-?\\d+,\\s*-?\\d+)\\)"
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Falcon       | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process execution events from Windows endpoints.
- **Required Artifacts:** Process execution logs, command line arguments.

---

## Considerations

- Investigate the context and intent of the `resizeTo` or `moveTo` usage.
- Review the parent process and user context for additional signs of compromise.
- Correlate with other suspicious behaviors, such as network connections or file writes.

---

## False Positives

False positives may occur if:
- Legitimate automation or deployment tools use these functions for benign purposes.
- Internal IT scripts invoke `mshta.exe` with window manipulation for valid reasons.

---

## Recommended Response Actions

1. Investigate the command line and script content for malicious intent.
2. Validate the legitimacy of the window manipulation and its source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1218.005 – Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [LOLBAS: Mshta](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
- [CrowdStrike: Detecting Malicious Mshta Usage](https://www.crowdstrike.com/blog/detecting-malicious-mshta-usage/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect hidden mshta window executions                                |
