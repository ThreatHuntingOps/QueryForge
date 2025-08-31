# Potential Mshta Web Content Execution Hunt Query Documentation

## Overview
This hunt query identifies executions of `mshta.exe` that leverage files hosted on remote web servers, which may indicate adversary activity. The query detects command lines containing strings consistent with domain names and extracts the remote resource URL for further analysis. Such executions are often used in phishing, malware delivery, and living-off-the-land attacks.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `mshta.exe`.
- Filters for command lines containing `//`, which is consistent with URLs or domain names.
- Extracts the remote resource (URL) from the command line using regex.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Potential Mshta Web Content Execution 
#event_simpleName=ProcessRollup2 
| FileName=mshta.exe 
| CommandLine="*//*" 
| rex field=CommandLine "(?i)(?<RemoteResource>(https?):\\/\\/([a-z]|\\d|\\.|\\/|_|-|:|\\)+)"
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

- Investigate the remote resource URL and its reputation.
- Review the parent process and user context for additional signs of compromise.
- Correlate with other suspicious behaviors, such as network connections or file writes.

---

## False Positives

False positives may occur if:
- Legitimate automation or deployment tools use remote web resources with `mshta.exe`.
- Internal IT scripts invoke `mshta.exe` with remote URLs for benign reasons.

---

## Recommended Response Actions

1. Investigate the remote resource URL and its source.
2. Validate the legitimacy of the web content and its reputation.
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
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect mshta executions with remote web content                      |
