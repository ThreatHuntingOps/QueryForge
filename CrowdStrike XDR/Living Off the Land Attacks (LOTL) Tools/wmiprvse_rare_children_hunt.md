# Rare Child Processes to WMIPrvSE Hunt Query Documentation

## Overview
This hunt query identifies suspicious or rare child processes spawned by `WMIPrvSE.exe`. It excludes command lines referencing common benign activity, such as PowerShell scripts (`.ps1`) and VBScript files (`.vbs`) under `C:\Windows\CCM\SystemTemp\`, as well as Managed Object Format (`.mof`) files under `C:\Windows\Temp\`. This helps surface anomalous or potentially malicious activity involving WMI.

---

## Hunt Query Logic

- Retrieves all process execution events where the process is `WMIPrvSE.exe` (case-insensitive).
- Excludes command lines referencing:
  - PowerShell (`.ps1`) or VBScript (`.vbs`) files in `C:\Windows\CCM\SystemTemp\`
  - `.mof` files in `C:\Windows\Temp\`
- Surfaces rare or unexpected child processes for further investigation.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Rare Child Processes to WMIPrvSE 
#event_simpleName=ProcessRollup2 
| FileName=/WMIPrvSE.exe/i 
| rex CommandLine!="(?i)((WINDOWS\\CCM\\SystemTemp\\.+\.(ps1|vbs))|(WINDOWS\\TEMP\\.+\.mof))"
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

- Investigate any non-standard child process spawned by `WMIPrvSE.exe`.
- Review the command line and context of the child process for signs of malicious activity.
- Correlate with other suspicious behaviors, such as file writes or network connections.

---

## False Positives

False positives may occur if:
- Legitimate management or automation tools invoke child processes from `WMIPrvSE.exe`.
- Internal scripts or IT operations use WMI for valid purposes.

---

## Recommended Response Actions

1. Investigate the child process and its command line.
2. Validate the legitimacy of the child process and its source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [LOLBAS: WMI](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wmi/)
- [CrowdStrike: Detecting Malicious WMI Usage](https://www.crowdstrike.com/blog/detecting-malicious-wmi-usage/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect rare child processes to WMIPrvSE                              |
