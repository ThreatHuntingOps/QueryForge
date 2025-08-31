# Suspicious Mshta File Execution Hunt Query Documentation

## Overview
This hunt query identifies anomalous executions of `mshta.exe` that do not involve inline script functionality. It focuses on cases where `.hta` files are executed, which is a common technique for delivering malicious payloads via HTML Application (HTA) files. The query uses regex to extract the `.hta` file path and filename from the command line for further analysis.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `mshta.exe`.
- Excludes executions involving inline script functionality such as `vbscript:`, `about:`, or `javascript:`.
- Excludes default embedding behavior for `mshta.exe`.
- Extracts the `.hta` file path from the command line using regex.
- Further parses the path to separate the folder and file name for investigation.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Suspicious Mshta File Execution 
#event_simpleName=ProcessRollup2 
| FileName=mshta.exe 
| FileName!="vbscript" or FileName!="about:" or FileName!="javascript:" 
| regex CommandLine!="(?i)mshta(?:\.exe)?\"?(?:\\s+-Embedding|$)" 
| rex field=CommandLine "(?i)mshta(?:\\.exe)?\"?\\s+\"?(?<HtaPath>(?:.*?\\.hta|(?<=\").*?(?=\")|.*?(?=(?:\\s|$))))" 
| rex field=HtaPath "(?i)(?<HtaFolder>.*)(\\\\|\\/)" 
| rex field=HtaPath "(?i)(.*(\\\\|\\/))?(?<HtaFile>.*)$" 
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

- Investigate the `.hta` file path and its source.
- Review the parent process and user context for additional signs of compromise.
- Correlate with other suspicious behaviors, such as network connections or file writes.

---

## False Positives

False positives may occur if:
- Legitimate automation or deployment tools use `.hta` files for valid purposes.
- Internal IT scripts invoke `mshta.exe` with `.hta` files for benign reasons.

---

## Recommended Response Actions

1. Investigate the `.hta` file path and its source.
2. Validate the legitimacy of the `.hta` file and its content.
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
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect suspicious mshta file executions                               |
