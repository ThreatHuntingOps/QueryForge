# Correlate Ransomware Execution with Creation of Impact Artifacts

## Severity or Impact of the Detected Behavior
- **Risk Score:** 99
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Ransomware-ImpactArtifacts
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with ransomware impact and data destruction. It identifies when ransomware (`ELPACO-team.exe` or `svhostss.exe`) creates files like `MIMIC_LOG.txt` and `session.tmp` in `C:	emp\`, indicating impact and possible data destruction.

Detected behaviors include:

- Execution of ransomware (`ELPACO-team.exe` or `svhostss.exe`)
- File creation of impact artifacts (`MIMIC_LOG.txt`, `session.tmp`) in `C:	emp\`
- Correlation of these events by process context, indicating ransomware impact and possible data destruction

Such activity is a strong indicator of data encryption for impact and data destruction by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |
| TA0040 - Impact              | T1485       | —            | Data Destruction                              |

---

## Hunt Query Logic

This query identifies when ransomware creates impact artifacts in `C:	emp\`, a strong indicator of ransomware impact and data destruction.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: ELPACO-team.exe or svhostss.exe execution    
#event_simpleName=ProcessRollup2    
| FileName="ELPACO-team.exe" or FileName="svhostss.exe"    
| join(    
  {    
    // Inner query: file creation of impact artifacts    
    #event_simpleName=FileCreate    
    | FileName="MIMIC_LOG.txt" or FileName="session.tmp"    
    | FilePath="C:\\temp\\"    
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

- **Required Permissions:** Attacker must be able to execute ransomware and write files to `C:	emp\`.
- **Required Artifacts:** Process creation logs, file creation logs, process context correlation.

---

## Considerations

- Validate the context of the ransomware execution and artifact creation to reduce false positives.
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
2. Investigate the source and intent of the ransomware execution and artifact creation.
3. Review all processes and files associated with the activity for further malicious behavior.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1485 – Data Destruction](https://attack.mitre.org/techniques/T1485/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-29 | Initial Detection | Created hunt query to detect ransomware execution with creation of impact artifacts |
