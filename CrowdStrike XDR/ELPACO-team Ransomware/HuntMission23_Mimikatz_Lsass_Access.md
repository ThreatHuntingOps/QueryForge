# Correlate Mimikatz/ProcessHacker Execution with LSASS Access

## Severity or Impact of the Detected Behavior
- **Risk Score:** 99
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MimikatzLSASSAccess
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with credential dumping. It identifies execution of `mimikatz.exe` or `ProcessHacker.exe` followed by access to `lsass.exe` with suspicious access flags (`0x1010`), which is a strong indicator of credential dumping attempts targeting LSASS memory.

Detected behaviors include:

- Execution of `mimikatz.exe` or `ProcessHacker.exe`
- The tool accessing `lsass.exe` with suspicious access flags (`0x1010`)
- Correlation of these events by process context, indicating credential dumping

Such activity is a strong indicator of credential access and post-exploitation activity by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0006 - Credential Access   | T1003       | 001          | OS Credential Dumping: LSASS Memory           |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                             |

---

## Hunt Query Logic

This query identifies when `mimikatz.exe` or `ProcessHacker.exe` accesses `lsass.exe` with suspicious access flags, a strong indicator of credential dumping.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: mimikatz or ProcessHacker execution    
#event_simpleName=ProcessRollup2    
| FileName=/mimikatz\.exe|ProcessHacker\.exe/i    
| join(    
  {    
    // Inner query: process access to lsass.exe with 0x1010    
    #event_simpleName=ProcessAccess    
    | TargetProcessName="lsass.exe"    
    | GrantedAccess="0x1010"    
  }    
  , field=TargetProcessId    
  , key=SourceProcessId    
  , include=[TargetProcessName, GrantedAccess]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, TargetProcessName, GrantedAccess]))    
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A              | ProcessAccess          | Process             | Process Access         |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as mimikatz or ProcessHacker and access LSASS memory.
- **Required Artifacts:** Process creation logs, process access logs, process context correlation.

---

## Considerations

- Validate the context of the tool execution and LSASS access to reduce false positives.
- Confirm that the activity is not part of legitimate security testing or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate penetration testing or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized LSASS access is detected.
2. Investigate the source and intent of the tool execution and LSASS access.
3. Review all processes associated with the tool and LSASS for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect Mimikatz/ProcessHacker execution and LSASS access |
