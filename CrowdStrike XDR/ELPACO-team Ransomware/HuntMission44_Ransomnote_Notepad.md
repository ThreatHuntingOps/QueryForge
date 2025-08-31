# Correlate Ransomware Execution with Notepad Viewing Ransom Note

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RansomNote-Notepad
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with ransomware impact and ransom note delivery. It identifies when Notepad is used to open the ransom note (`Decryption_INFO.txt`) after ransomware execution (`ELPACO-team.exe` or `svhostss.exe`).

Detected behaviors include:

- Execution of `notepad.exe` with `Decryption_INFO.txt` in the command line
- Prior or concurrent execution of `ELPACO-team.exe` or `svhostss.exe` on the same host
- Correlation of these events by asset ID, indicating ransom note viewing after ransomware impact

Such activity is a strong indicator of data encryption for impact and system recovery inhibition by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |
| TA0040 - Impact              | T1490       | —            | Inhibit System Recovery                       |

---

## Hunt Query Logic

This query identifies when Notepad is used to open the ransom note after ransomware execution, a strong indicator of ransomware impact and ransom note delivery.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: notepad.exe execution with ransom note    
#event_simpleName=ProcessRollup2    
| FileName="notepad.exe"    
| CommandLine=/Decryption_INFO\.txt/i    
| join(    
  {    
    // Inner query: ELPACO-team.exe or svhostss.exe execution on same host    
    #event_simpleName=ProcessRollup2    
    | FileName="ELPACO-team.exe" or FileName="svhostss.exe"    
  }    
  , field=aid    
  , key=aid    
  , include=[FileName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, CommandLine]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute ransomware and open ransom note files.
- **Required Artifacts:** Process creation logs, process context correlation.

---

## Considerations

- Validate the context of the notepad.exe execution and ransom note viewing to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and file activity for signs of further exploitation or impact.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate incident response or testing.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized ransomware activity is detected.
2. Investigate the source and intent of the ransomware execution and ransom note viewing.
3. Review all processes and files associated with the activity for further malicious behavior.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-29 | Initial Detection | Created hunt query to detect ransomware execution with notepad viewing ransom note |
