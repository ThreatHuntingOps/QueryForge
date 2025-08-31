# Correlate 7-Zip SFX Extraction and Ransomware Component Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-7ZipSFX-Ransomware
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with ransomware deployment using a 7-Zip SFX archive. It identifies when `ELPACO-team.exe` (7-Zip SFX) extracts and executes components like `7za.exe`, `svhostss.exe`, `Everything.exe`, `gui35.exe`, `gui40.exe`, `xdel.exe`, and `ENC_default_default_*.exe` in the temp or user AppData folders.

Detected behaviors include:

- Process creation of `ELPACO-team.exe`
- File creation of extracted ransomware components in temp or user AppData folders
- Correlation of these events by process context, indicating automated extraction and execution of ransomware payloads

Such activity is a strong indicator of data encryption for impact, ingress tool transfer, and use of command and scripting interpreters by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |
| TA0009 - Collection          | T1105       | —            | Ingress Tool Transfer                         |
| TA0002 - Execution           | T1059       | —            | Command and Scripting Interpreter             |

---

## Hunt Query Logic

This query identifies when `ELPACO-team.exe` (7-Zip SFX) extracts and executes ransomware components in temp or user AppData folders, a strong indicator of ransomware deployment and execution.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: ELPACO-team.exe process creation    
#event_simpleName=ProcessRollup2    
| FileName="ELPACO-team.exe"    
| join(    
  {    
    // Inner query: file creation of extracted components    
    #event_simpleName=FileCreate    
    | FileName=/7za\.exe|svhostss\.exe|Everything\.exe|gui35\.exe|gui40\.exe|xdel\.exe|ENC_default_default_.*\.exe/i    
    | FilePath=/C:\\Users\\noname\\AppData\\Local\\Temp\\5\\7ZipSfx\.000\\|C:\\Users\\noname\\AppData\\Local\\F6A3737E-E3B0-8956-8261-0121C68105F3\\/i 
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[FileName, FilePath]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, FilePath]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A              | FileCreate             | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute 7-Zip SFX and write files to temp or AppData folders.
- **Required Artifacts:** Process creation logs, file creation logs, process context correlation.

---

## Considerations

- Validate the context of the SFX extraction and component execution to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate software deployment or testing with similar tools.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized ransomware deployment is detected.
2. Investigate the source and intent of the SFX extraction and component execution.
3. Review all processes associated with the ransomware and extracted files for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-29 | Initial Detection | Created hunt query to detect 7-Zip SFX extraction and ransomware component execution |
