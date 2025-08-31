# Correlate Execution of Defender Control with Disabling Windows Defender

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-DefenderControlDisable
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with defense evasion. It identifies execution of `DC.exe` (Defender Control) followed by modification of the registry key to disable Windows Defender (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` set to `1`). This pattern is strongly associated with attempts to disable endpoint protection and evade detection.

Detected behaviors include:

- Execution of `DC.exe` (Defender Control)
- Registry modification to disable Windows Defender
- Correlation of these events by process context, indicating automated or manual defense evasion

Such activity is a strong indicator of defense evasion and possible prelude to further malicious activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1562       | 001          | Impair Defenses: Disable or Modify Tools      |
| TA0005 - Defense Evasion     | T1112       | —            | Modify Registry                               |

---

## Hunt Query Logic

This query identifies execution of Defender Control (`DC.exe`) followed by registry modification to disable Windows Defender. This sequence is a strong indicator of defense evasion.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: DC.exe execution    
#event_simpleName=ProcessRollup2    
| FileName="DC.exe"    
| join(    
  {    
    // Inner query: registry modification to disable Defender    
    #event_simpleName=RegistryModification    
    | RegistryKey="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"  
    | RegistryValue=1    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[RegistryKey, RegistryValue]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, RegistryKey, RegistryValue]))
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A              | RegistryModification   | Registry            | Registry Key Modification |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as Defender Control and modify registry keys.
- **Required Artifacts:** Process creation logs, registry modification logs, process context correlation.

---

## Considerations

- Validate the context of the Defender Control execution and registry modification to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately use Defender Control for troubleshooting or testing.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network.
2. Investigate the source and intent of the Defender Control execution and registry modification.
3. Review all processes associated with Defender Control and registry changes for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Re-enable Windows Defender and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK: T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect Defender Control execution and Defender disablement |
