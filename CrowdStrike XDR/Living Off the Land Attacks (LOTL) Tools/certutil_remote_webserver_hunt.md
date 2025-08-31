# Certutil Executions Referencing a Remote Web Server Hunt Query Documentation

## Overview
This hunt query identifies executions of `certutil.exe` that reference a remote web server, which may be indicative of arbitrary file downloads. Adversaries often abuse `certutil.exe` to download malicious payloads from the internet, leveraging its presence on Windows systems to bypass security controls.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `certutil.exe`.
- Filters for command lines containing `http:` or `https:`, indicating a reference to a remote web server.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Certutil executions referencing a remote web server 
#event_simpleName=ProcessRollup2 
| FileName=certutil.exe 
| CommandLine="*http:*" or CommandLine="*https:*"
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

- Investigate the remote URL and its reputation.
- Review the parent process and user context for additional signs of compromise.
- Correlate with other suspicious behaviors, such as file writes or subsequent process executions.

---

## False Positives

False positives may occur if:
- Legitimate administrative or automation scripts use `certutil.exe` to download files from trusted sources.
- Internal IT tools invoke `certutil.exe` with remote URLs for benign reasons.

---

## Recommended Response Actions

1. Investigate the remote URL and its source.
2. Validate the legitimacy of the download and its content.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [LOLBAS: Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [CrowdStrike: Detecting Malicious Certutil Usage](https://www.crowdstrike.com/blog/detecting-malicious-certutil-usage/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect certutil executions referencing remote web servers             |
