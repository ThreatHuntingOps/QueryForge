# Correlate PowerShell VM Discovery/Manipulation with Ransomware Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-PowerShell-VM-Ransomware
- **Operating Systems:** WindowsServer, WindowsEndpoint, Hypervisor
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with ransomware targeting virtual machines. It identifies PowerShell commands for VM discovery and manipulation (e.g., `Get-VM`, `Get-VHD`, `Dismount-DiskImage`, `Stop-VM`) in proximity to ransomware execution (`ELPACO-team.exe` or `svhostss.exe`).

Detected behaviors include:

- Execution of `powershell.exe` with VM-related commands
- Prior or concurrent execution of ransomware on the same host
- Correlation of these events by asset ID, indicating ransomware targeting of virtualized infrastructure

Such activity is a strong indicator of ransomware targeting VMs for encryption and impact.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |
| TA0007 - Discovery           | T1087       | —            | Account Discovery                             |
| TA0002 - Execution           | T1059       | 001          | PowerShell                                    |

---

## Hunt Query Logic

This query identifies when PowerShell is used for VM discovery/manipulation in proximity to ransomware execution, a strong indicator of ransomware targeting virtualized assets.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: powershell.exe execution with VM-related commands    
#event_simpleName=ProcessRollup2    
| FileName="powershell.exe"    
| CommandLine=/Get-VM|Get-VHD|Dismount-DiskImage|Stop-VM/i    
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

- **Required Permissions:** Attacker must be able to execute PowerShell and ransomware on the same host.
- **Required Artifacts:** Process creation logs, process context correlation.

---

## Considerations

- Validate the context of the PowerShell execution and VM manipulation to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and system activity for signs of further exploitation or impact.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate VM management or ransomware testing.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized VM manipulation or ransomware activity is detected.
2. Investigate the source and intent of the PowerShell and ransomware execution.
3. Review all processes and files associated with the activity for further malicious behavior.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-29 | Initial Detection | Created hunt query to detect PowerShell VM discovery/manipulation with ransomware execution |
