# Correlate netscan.exe Spawning mstsc.exe for RDP Lateral Movement

## Severity or Impact of the Detected Behavior
- **Risk Score:** 94
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-NetscanMstscRDP
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with lateral movement via RDP initiated from a discovery tool. It identifies when `netscan.exe` spawns `mstsc.exe` (Remote Desktop Connection), indicating that RDP lateral movement is being initiated directly from a network discovery tool.

Detected behaviors include:

- Process creation of `netscan.exe`
- `netscan.exe` spawning `mstsc.exe` (Remote Desktop Connection)
- Correlation of these events by process context, indicating automated or tool-assisted lateral movement

Such activity is a strong indicator of lateral movement, ingress tool transfer, and account discovery by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021       | 001          | Remote Services: Remote Desktop Protocol       |
| TA0009 - Collection          | T1105       | —            | Ingress Tool Transfer                         |
| TA0007 - Discovery           | T1087       | —            | Account Discovery                             |

---

## Hunt Query Logic

This query identifies when `netscan.exe` spawns `mstsc.exe`, a strong indicator of RDP lateral movement initiated from a discovery tool.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: netscan.exe process creation    
#event_simpleName=ProcessRollup2    
| FileName="netscan.exe"    
| join(    
  {    
    // Inner query: mstsc.exe spawned by netscan.exe    
    #event_simpleName=ProcessRollup2    
    | ParentBaseFileName="netscan.exe"    
    | FileName="mstsc.exe"    
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

- **Required Permissions:** Attacker must be able to execute code as netscan and spawn mstsc.exe.
- **Required Artifacts:** Process creation logs, process context correlation.

---

## Considerations

- Validate the context of the netscan and mstsc.exe execution to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate network scanning and RDP sessions.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized lateral movement is detected.
2. Investigate the source and intent of the netscan and mstsc.exe execution.
3. Review all processes associated with the tools for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-28 | Initial Detection | Created hunt query to detect netscan spawning mstsc.exe for RDP lateral movement |
