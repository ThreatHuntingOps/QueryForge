# Correlate Batch Script Execution with Mimikatz Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-BatchMimikatz
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with credential dumping via batch script automation. It identifies execution of a batch script (e.g., `!start.cmd`) that launches both 32-bit and 64-bit versions of `mimikatz.exe`, a common attacker tradecraft for credential dumping and privilege escalation.

Detected behaviors include:

- Execution of a batch script (`!start.cmd`)
- The script launching `mimikatz.exe` from the same folder (potentially both 32-bit and 64-bit versions)
- Correlation of these events by process context, indicating automated credential dumping

Such activity is a strong indicator of credential access and post-exploitation activity by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059       | —            | Command and Scripting Interpreter             |
| TA0006 - Credential Access   | T1003       | 001          | OS Credential Dumping: LSASS Memory           |

---

## Hunt Query Logic

This query identifies when a batch script (`!start.cmd`) launches `mimikatz.exe` from the same folder, a strong indicator of automated credential dumping.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: batch script execution    
#event_simpleName=ProcessRollup2    
| FileName="!start.cmd"    
| join(    
  {    
    // Inner query: mimikatz.exe execution from same folder    
    #event_simpleName=ProcessRollup2    
    | FileName="mimikatz.exe"    
  }    
  , field=TargetProcessId    
  , key=ParentProcessId    
  , include=[FileName, CommandLine]    
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

- **Required Permissions:** Attacker must be able to execute code as a batch script and launch Mimikatz.
- **Required Artifacts:** Process creation logs, process context correlation.

---

## Considerations

- Validate the context of the batch script and Mimikatz execution to reduce false positives.
- Confirm that the activity is not part of legitimate security testing or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate penetration testing or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized credential dumping is detected.
2. Investigate the source and intent of the batch script and Mimikatz execution.
3. Review all processes associated with the script and Mimikatz for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect batch script and Mimikatz activity |
