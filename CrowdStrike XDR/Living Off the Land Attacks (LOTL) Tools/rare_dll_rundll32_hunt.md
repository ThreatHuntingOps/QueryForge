# Rare DLL Files Loaded via Rundll32 Hunt Query Documentation

## Overview
This hunt query identifies rare or unusual DLL files loaded by `rundll32.exe` on Windows systems. By extracting DLL file paths and entrypoints from the command line, analysts can surface low-prevalence DLLs or suspicious entrypoints that may indicate malicious activity, such as DLL side-loading or execution of attacker-controlled code.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `rundll32.exe`.
- Extracts the DLL file path and entrypoint from the command line using regular expressions.
- Further parses the DLL path to separate the folder and DLL file name.
- Surfaces DLLs and entrypoints that are rare or unexpected for further investigation.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 
| FileName=rundll32.exe 
| rex field=CommandLine "(?i)(?<DLLPath>(?:\"(?:[^\"]*\\.dll)\"(?:\\s|,))|(?:[^ ]*\\.dll)(?:\\s|,))\\s*(?<EntryPoint>.+?)(\\s|$)" 
| rex field=DLLPath "(?i)(?<DLLFolder>[^\"]*[\\\/])?(?<DLLFile>[^\"]+\\.dll)"
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
- Investigate DLL files and entrypoints that are rare or not commonly seen in your environment.
- Review the source and signature of the DLL file.
- Correlate with other suspicious activity, such as unusual parent processes or network connections.

---

## False Positives
False positives may occur if:
- Legitimate software uses custom or rarely seen DLLs for valid purposes.
- Internal tools or scripts invoke rundll32 with uncommon DLLs.

---

## Recommended Response Actions
1. Investigate the context of the DLL file and entrypoint loaded by rundll32.
2. Validate the DLL's signature and source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1218.011 – Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [CrowdStrike: Detecting DLL Side-Loading](https://www.crowdstrike.com/blog/detecting-dll-side-loading/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect rare DLL files loaded via rundll32                            |
