# Suspicious Certutil Encoding/Decoding Hunt Query Documentation

## Overview
This hunt query identifies executions of `certutil.exe` leveraging its Base64-related functionality via the encode or decode command-line options. Adversaries often abuse these options to encode or decode payloads, exfiltrate data, or bypass security controls.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `certutil.exe`.
- Filters for command lines containing `-encode`, `-decode`, `/encode`, or `/decode`.
- Extracts the operation type (encode/decode), input file, and output file from the command line using regex.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Suspicious Encoding/Decoding 
#event_simpleName=ProcessRollup2 
| FileName=certutil.exe 
| CommandLine="*-encode*" OR CommandLine="*-decode*" OR CommandLine="*/encode*" OR CommandLine="*/decode*" 
| rex field=CommandLine "(?i)(?<Operation>\\w+code)\\s+(?<InputFile>\".*?\"|.*?)\\s+(?<OutputFile>\".*?\"|.*?)($|\\s)" 
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

- Investigate the input and output files involved in the encoding or decoding operation.
- Review the parent process and user context for additional signs of compromise.
- Correlate with other suspicious behaviors, such as file writes or subsequent process executions.

---

## False Positives

False positives may occur if:
- Legitimate administrative or automation scripts use `certutil.exe` for encoding or decoding files.
- Internal IT tools invoke `certutil.exe` with these options for benign reasons.

---

## Recommended Response Actions

1. Investigate the input and output files and their contents.
2. Validate the legitimacy of the encoding/decoding operation.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1140 – Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [LOLBAS: Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [CrowdStrike: Detecting Malicious Certutil Usage](https://www.crowdstrike.com/blog/detecting-malicious-certutil-usage/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect suspicious certutil encoding/decoding operations              |
