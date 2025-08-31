# Correlate Metasploit Loader with SYSTEM-Level cmd.exe Spawn

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MetasploitSystemCmd
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with successful privilege escalation via Metasploit. It identifies when the Metasploit loader (e.g., `HAHLGiDDb.exe`) spawns `cmd.exe` processes running as `NT AUTHORITY\SYSTEM`, indicating the attacker has achieved SYSTEM-level privileges. This pattern is strongly associated with exploitation for privilege escalation and post-exploitation command execution.

Detected behaviors include:

- Creation of the Metasploit loader process (`HAHLGiDDb.exe`)
- The loader spawning `cmd.exe` running as `NT AUTHORITY\SYSTEM`
- Correlation of these events by process context, indicating successful privilege escalation

Such activity is a strong indicator of SYSTEM-level access and post-exploitation command execution by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0004 - Privilege Escalation| T1068       | —            | Exploitation for Privilege Escalation         |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                             |
| TA0002 - Execution           | T1059       | —            | Command and Scripting Interpreter             |

---

## Hunt Query Logic

This query identifies when the Metasploit loader spawns `cmd.exe` running as SYSTEM, indicating successful privilege escalation and post-exploitation command execution.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: Metasploit loader process creation    
#event_simpleName=ProcessRollup2    
| FileName="HAHLGiDDb.exe"    
| join(    
  {    
    // Inner query: cmd.exe spawned by loader, running as SYSTEM    
    #event_simpleName=ProcessRollup2    
    | FileName="cmd.exe"    
    | UserName="NT AUTHORITY\\SYSTEM"    
  }    
  , field=TargetProcessId    
  , key=ParentProcessId    
  , include=[FileName, UserName, CommandLine]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, UserName, CommandLine]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as the Metasploit loader and spawn SYSTEM-level processes.
- **Required Artifacts:** Process creation logs, user context, process context correlation.

---

## Considerations

- Validate the context of the SYSTEM-level process creation to reduce false positives.
- Confirm that the SYSTEM-level `cmd.exe` is not part of legitimate administrative or update activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or automated tools legitimately spawn SYSTEM-level `cmd.exe` from custom loaders.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the SYSTEM-level `cmd.exe` spawn.
3. Review all processes associated with the loader and SYSTEM-level `cmd.exe` for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect Metasploit loader and SYSTEM-level cmd.exe spawn |
