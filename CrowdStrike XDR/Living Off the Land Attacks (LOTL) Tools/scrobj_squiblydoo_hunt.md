# Suspicious scrobj.dll Executions (Squiblydoo Technique) Hunt Query Documentation

## Overview
This hunt query identifies executions of `regsvr32.exe` with `scrobj.dll` in the command line, a hallmark of the Squiblydoo technique. This method is often used by attackers to execute remote or local scripts via `regsvr32` without writing files to disk, bypassing traditional application whitelisting and detection controls.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `regsvr32.exe`.
- Filters for command lines containing `scrobj.dll` and the `i:` argument, which is used to specify a script file.
- Extracts the script file path or URL from the command line for further analysis.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Suspicious scrobj.dll Executions 
#event_simpleName=ProcessRollup2 
| FileName=regsvr32.exe 
| CommandLine=crobj.dll CommandLine=/\\*i:/ 
| rex field=CommandLine "(?i)i:\\s*(?<ScriptFile>(?:\"[^\"]*?\")|(?:[^ ]*?(\\s|$)))" 
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

- Investigate the source and content of the script file or URL specified in the command line.
- Review the parent process and user context for additional signs of compromise.
- Correlate with other suspicious activity, such as network connections or file writes.

---

## False Positives

False positives may occur if:
- Legitimate administrative scripts use `regsvr32.exe` with `scrobj.dll` for automation.
- Internal tools or testing frameworks invoke this technique for benign purposes.

---

## Recommended Response Actions

1. Investigate the script file or URL specified in the command line.
2. Validate the legitimacy of the script and its source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1218.010 – Regsvr32](https://attack.mitre.org/techniques/T1218/010/)
- [FireEye: Squiblydoo – New Regsvr32 Bypass](https://www.fireeye.com/blog/threat-research/2016/03/fin7_spear_phishing.html)
- [LOLBAS: Regsvr32](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect suspicious scrobj.dll executions (Squiblydoo technique)        |
