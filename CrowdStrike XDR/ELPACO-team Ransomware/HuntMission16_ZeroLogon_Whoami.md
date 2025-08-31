# Correlate Zerologon Exploitation Attempt with whoami Command Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 99
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-ZerologonWhoami
- **Operating Systems:** WindowsServer, DomainController
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Zerologon exploitation and privilege escalation verification. It identifies execution of `zero.exe` (Zerologon exploit tool) against domain controllers, followed by a `whoami` command, indicating an attempt to verify successful privilege escalation. This pattern is strongly associated with exploitation for privilege escalation and post-exploitation command execution.

Detected behaviors include:

- Execution of `zero.exe` with command-line arguments targeting the administrator and running `whoami`
- The same process spawning `whoami.exe` to verify privilege escalation
- Correlation of these events by process context, indicating exploitation and verification

Such activity is a strong indicator of Zerologon exploitation and post-exploitation verification by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0004 - Privilege Escalation| T1068       | —            | Exploitation for Privilege Escalation         |
| TA0006 - Credential Access   | T1078       | —            | Valid Accounts                                |
| TA0002 - Execution           | T1059       | —            | Command and Scripting Interpreter             |

---

## Hunt Query Logic

This query identifies execution of `zero.exe` with administrator and whoami command-line arguments, followed by execution of `whoami.exe` by the same process. This sequence is a strong indicator of Zerologon exploitation and privilege escalation verification.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: zero.exe execution    
#event_simpleName=ProcessRollup2    
| FileName="zero.exe"    
| CommandLine=/administrator -c "whoami"/i    
| join(    
  {    
    // Inner query: whoami.exe execution by same process    
    #event_simpleName=ProcessRollup2    
    | FileName="whoami.exe"    
  }    
  , field=TargetProcessId    
  , key=ParentProcessId    
  , include=[FileName, CommandLine]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, CommandLine]))   
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as the exploit tool and spawn child processes.
- **Required Artifacts:** Process creation logs, command-line arguments, process context correlation.

---

## Considerations

- Validate the context of the zero.exe and whoami.exe execution to reduce false positives.
- Confirm that the execution is not part of legitimate security testing or administrative activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate penetration testing or red team exercises.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected domain controller from the network.
2. Investigate the source and intent of the zero.exe and whoami.exe execution.
3. Review all processes associated with the exploit and verification for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable domain controllers and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK: T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect Zerologon exploitation and whoami verification |
