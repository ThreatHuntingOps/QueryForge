# MSBuild Executions with Logger Hunt Query Documentation

## Overview
This hunt query identifies executions of `msbuild.exe` that specify a DLL path using the `-logger` option. While MSBuild is frequently used legitimately (including by CI/CD and automation frameworks), adversaries may abuse the logger functionality to load malicious DLLs. This query acts as a starting point and may need to be tuned for your environment.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `msbuild.exe`.
- Filters for command lines containing `/logger:` or `-logger:`, which specify a logger DLL.
- Extracts the logger name and DLL path from the command line using regex for further analysis.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
 // MSBuild Executions with Logger 
#event_simpleName=ProcessRollup2 
| FileName=msbuild.exe 
| CommandLine="*/logger:*" OR CommandLine="*-logger:*" 
| rex field=CommandLine "(?i)logger:\\s*((?<Logger>.*?),)?(?<LoggerPath>(\".*?\\.\\w{3,}\"|.+?\\.\\w{3,}(\\s|$|;)))" 
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

- Investigate the DLL path specified with the `-logger` option, especially if it is located in non-standard directories.
- Review the parent process and user context for additional signs of compromise.
- Correlate with other suspicious behaviors, such as file writes or network connections.

---

## False Positives

False positives may occur if:
- Legitimate build or deployment tools use custom loggers for valid purposes.
- Internal automation scripts invoke `msbuild.exe` with logger DLLs.

---

## Recommended Response Actions

1. Investigate the logger DLL path and its source.
2. Validate the legitimacy of the DLL and its signature.
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
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect msbuild executions with logger DLLs                           |
