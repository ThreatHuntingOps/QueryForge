# Rundll32 Spawned by Suspicious Parent Processes Hunt Query Documentation

## Overview
This hunt query identifies instances where `rundll32.exe` is spawned by parent processes that are commonly abused in successful intrusions. These include Microsoft Office applications (Word, PowerPoint, Excel, Outlook) and scripting engines (Mshta, Windows Script Host). Such parent-child relationships are often associated with phishing, macro-based attacks, and script-based malware delivery.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `rundll32.exe`.
- Filters for cases where the parent process is one of the following:
  - `winword.exe` (Microsoft Word)
  - `powerpnt.exe` (Microsoft PowerPoint)
  - `excel.exe` (Microsoft Excel)
  - `outlook.exe` (Microsoft Outlook)
  - `mshta.exe` (Microsoft HTML Application Host)
  - `cscript.exe` (Windows Script Host - Console)
  - `wscript.exe` (Windows Script Host - Windows)

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Common Suspicious Parents
#event_simpleName=ProcessRollup2 
| FileName=rundll32.exe  
| ParentBaseFileName=winword.exe or ParentBaseFileName=powerpnt.exe or ParentBaseFileName=excel.exe or ParentBaseFileName=outlook.exe or ParentBaseFileName=mshta.exe or ParentBaseFileName=cscript.exe or ParentBaseFileName=wscript.exe
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

- Investigate the context of `rundll32.exe` execution, especially when spawned by productivity or scripting applications.
- Review the command line and loaded DLLs for signs of malicious activity.
- Correlate with other suspicious behaviors, such as document-based phishing or script-based attacks.

---

## False Positives

False positives may occur if:
- Legitimate add-ins or automation tools use Office or scripting hosts to launch `rundll32.exe`.
- Internal scripts or macros invoke `rundll32.exe` for valid reasons.

---

## Recommended Response Actions

1. Investigate the parent process and user context for the `rundll32.exe` execution.
2. Analyze the command line and loaded DLLs for suspicious indicators.
3. Review related document or script files for malicious content.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1218.011 – Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [CrowdStrike: Detecting Malicious Rundll32 Usage](https://www.crowdstrike.com/blog/detecting-malicious-rundll32-usage/)
- [Microsoft: Office Macro Threats](https://www.microsoft.com/security/blog/2022/07/08/office-macro-threats/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect suspicious rundll32 executions with high-risk parent processes |
