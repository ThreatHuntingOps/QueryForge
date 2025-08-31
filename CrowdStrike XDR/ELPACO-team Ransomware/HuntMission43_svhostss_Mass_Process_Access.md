# Correlate svhostss.exe with Mass Process Access

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-svhostss-MassProcessAccess
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with credential theft or process manipulation. It identifies when `svhostss.exe` accesses many processes, especially `lsass.exe` and `svchost.exe`, with suspicious access flags (`0x40`, `0x121411`), indicating possible credential theft or process injection.

Detected behaviors include:

- Process creation of `svhostss.exe`
- Process access to `lsass.exe` or `svchost.exe` with suspicious access flags
- Correlation of these events by process context, indicating mass process access and possible credential theft or process manipulation

Such activity is a strong indicator of OS credential dumping, process injection, and service manipulation by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1489       | —            | Impact: Service Stop                          |
| TA0006 - Credential Access   | T1003       | 001          | OS Credential Dumping: LSASS Memory           |
| TA0004 - Privilege Escalation| T1055       | —            | Process Injection                             |

---

## Hunt Query Logic

This query identifies when `svhostss.exe` accesses many processes, especially `lsass.exe` and `svchost.exe`, with suspicious access flags, a strong indicator of credential theft or process manipulation.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: svhostss.exe process creation    
#event_simpleName=ProcessRollup2    
| FileName="svhostss.exe"    
| join(    
  {    
    // Inner query: process access to lsass.exe or svchost.exe with suspicious flags    
    #event_simpleName=ProcessAccess    
    | TargetProcessName=/lsass\.exe|svchost\.exe/i    
    | (GrantedAccess="0x40" or GrantedAccess="0x121411")    
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

- **Required Permissions:** Attacker must be able to execute svhostss.exe and access other processes with elevated privileges.
- **Required Artifacts:** Process creation logs, process access logs, process context correlation.

---

## Considerations

- Validate the context of the svhostss.exe execution and process access to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and system activity for signs of further exploitation or privilege escalation.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate process access for diagnostics or monitoring.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized process access is detected.
2. Investigate the source and intent of the svhostss.exe execution and process access.
3. Review all processes and access patterns associated with the activity for further malicious behavior.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1489 – Impact: Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-29 | Initial Detection | Created hunt query to detect svhostss.exe with mass process access |
