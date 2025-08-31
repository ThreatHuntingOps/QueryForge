# Correlate rpcdump.exe Execution with Batch Script for PrintNightmare Discovery

## Severity or Impact of the Detected Behavior
- **Risk Score:** 91
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RpcdumpPrintNightmare
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with PrintNightmare vulnerability discovery using Impacket's `rpcdump.exe`. It identifies execution of `rpcdump.exe` via a batch script (e.g., `CheckVuln.bat`) with command-line arguments to enumerate RPC endpoints related to PrintNightmare (`MS-RPRN`, `MS-PAR`).

Detected behaviors include:

- Execution of a batch script (`CheckVuln.bat`)
- The script launching `rpcdump.exe` with PrintNightmare-related arguments (`MS-RPRN`, `MS-PAR`)
- Correlation of these events by process context, indicating automated vulnerability discovery

Such activity is a strong indicator of reconnaissance and vulnerability assessment by an attacker or red team.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery           | T1046       | —            | Network Service Discovery                     |
| TA0007 - Discovery           | T1087       | —            | Account Discovery                             |
| TA0007 - Discovery           | T1082       | —            | System Information Discovery                  |

---

## Hunt Query Logic

This query identifies when `rpcdump.exe` is executed via a batch script with PrintNightmare-related arguments, a strong indicator of vulnerability discovery.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: batch script execution (CheckVuln.bat)    
#event_simpleName=ProcessRollup2    
| FileName="CheckVuln.bat"    
| join(    
  {    
    // Inner query: rpcdump.exe execution with PrintNightmare arguments    
    #event_simpleName=ProcessRollup2    
    | FileName="rpcdump.exe"    
    | CommandLine=/MS-RPRN|MS-PAR/i    
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

- **Required Permissions:** Attacker must be able to execute code as a batch script and launch rpcdump.exe.
- **Required Artifacts:** Process creation logs, process context correlation.

---

## Considerations

- Validate the context of the batch script and rpcdump execution to reduce false positives.
- Confirm that the activity is not part of legitimate security testing or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate vulnerability assessments or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized vulnerability discovery is detected.
2. Investigate the source and intent of the batch script and rpcdump execution.
3. Review all processes associated with the script and rpcdump for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK: T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-28 | Initial Detection | Created hunt query to detect rpcdump execution via batch script for PrintNightmare |
