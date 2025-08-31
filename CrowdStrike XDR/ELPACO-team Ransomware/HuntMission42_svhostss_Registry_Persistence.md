# Correlate svhostss.exe Execution with Registry Run Key Persistence

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-svhostss-RegistryPersistence
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with malware persistence via the Windows Registry. It identifies when `svhostss.exe` is executed and persistence is established via the Windows Run registry key (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).

Detected behaviors include:

- Process creation of `svhostss.exe`
- Registry modification to add a Run key for `svhostss.exe` (`RegistryValueName="svhostss"`)
- Correlation of these events by process context, indicating malware persistence via registry autostart

Such activity is a strong indicator of boot or logon autostart execution and use of command and scripting interpreters by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence         | T1547       | 001          | Boot or Logon Autostart Execution: Registry Run Keys |
| TA0002 - Execution           | T1059       | —            | Command and Scripting Interpreter             |

---

## Hunt Query Logic

This query identifies when `svhostss.exe` is executed and persistence is established via the Windows Run registry key, a strong indicator of malware persistence and execution.

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
    // Inner query: registry modification for persistence    
    #event_simpleName=RegistryModification    
    | RegistryKey="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"    
    | RegistryValueName="svhostss"    
    | RegistryValue=/svhostss\.exe/i    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[RegistryKey, RegistryValueName, RegistryValue]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, RegistryKey, RegistryValueName, RegistryValue]))   
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A              | RegistryModification   | Registry            | Registry Modification  |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute svhostss.exe and modify the Windows Run registry key.
- **Required Artifacts:** Process creation logs, registry modification logs, process context correlation.

---

## Considerations

- Validate the context of the svhostss.exe execution and registry modification to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and registry activity for signs of further exploitation or persistence mechanisms.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate software deployment or registry modifications.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized persistence is detected.
2. Investigate the source and intent of the svhostss.exe execution and registry modification.
3. Review all processes and registry keys associated with the persistence mechanism for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-29 | Initial Detection | Created hunt query to detect svhostss.exe execution with registry run key persistence |
