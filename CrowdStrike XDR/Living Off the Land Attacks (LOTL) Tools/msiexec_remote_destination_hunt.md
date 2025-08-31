# Msiexec Executions with Remote Destination Hunt Query Documentation

## Overview
This hunt query identifies executions of `msiexec.exe` that leverage remotely hosted files, which may indicate adversary behavior. Specifically, it detects command lines specifying either `/i` (install) or `/x` (uninstall) followed by a URL beginning with `http:` or `https:`. Such executions are often used in malware delivery and lateral movement scenarios.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `msiexec.exe`.
- Filters for command lines containing `http` or `https`.
- Extracts the remote URL following `/i` or `/x` from the command line for further analysis.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Executions with Remote Destination 
#event_simpleName=ProcessRollup2 
| FileName=msiexec.exe 
| CommandLine="*http*" 
| rex field=CommandLine "(?i)[-/][ix]\\s*(?<URL>(?:\"https?:[^\"]*?\")|(?:https?:[^ ]*?(\\s|$)))"
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

- Validate the authenticity and reputation of the URLs found in the command line.
- Investigate the source and content of the remote MSI files.
- Review the parent process and user context for additional signs of compromise.

---

## False Positives

False positives may occur if:
- Legitimate software deployment tools use remote MSI files for installation or updates.
- Internal IT automation scripts invoke `msiexec.exe` with remote URLs.

---

## Recommended Response Actions

1. Investigate the remote URL and the MSI file it references.
2. Validate the legitimacy of the download source.
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
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect msiexec executions with remote destinations                    |
