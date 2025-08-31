# Correlate Registry Query and Modification for RDP Enablement

## Severity or Impact of the Detected Behavior
- **Risk Score:** 94
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RDPEnablement
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with enabling Remote Desktop Protocol (RDP) access via registry manipulation. It identifies registry queries for the RDP port and subsequent modifications to enable RDP connections (`fDenyTSConnections` set to `0`). This pattern is strongly associated with attempts to enable remote access, often as part of lateral movement or persistence.

Detected behaviors include:

- Registry query for the RDP port (`HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`)
- Registry modification to enable RDP (`fDenyTSConnections` set to `0`)
- Correlation of these events by process context, indicating automated or manual enablement of RDP

Such activity is a strong indicator of remote access enablement and possible lateral movement or persistence by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1112       | —            | Modify Registry                               |
| TA0005 - Defense Evasion     | T1562       | 001          | Impair Defenses: Disable or Modify Tools      |
| TA0008 - Lateral Movement    | T1021       | 001          | Remote Services: Remote Desktop Protocol      |

---

## Hunt Query Logic

This query identifies registry queries for the RDP port and subsequent modifications to enable RDP connections. This sequence is a strong indicator of remote access enablement and possible lateral movement or persistence.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: registry query for RDP port    
#event_simpleName=ProcessRollup2    
| CommandLine=/reg query "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" \/v PortNumber/i     
| join(    
  {    
    // Inner query: registry modification to enable RDP    
    #event_simpleName=RegistryModification    
    | RegistryKey="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"    
    | RegistryValueName="fDenyTSConnections"    
    | RegistryValue=0    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[RegistryKey, RegistryValueName, RegistryValue]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([CommandLine, RegistryKey, RegistryValueName, RegistryValue])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A              | RegistryModification   | Registry            | Registry Key Modification |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and modify registry keys.
- **Required Artifacts:** Process creation logs, registry modification logs, process context correlation.

---

## Considerations

- Validate the context of the registry query and modification to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately enable RDP for remote support or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized RDP enablement is detected.
2. Investigate the source and intent of the registry query and modification.
3. Review all processes associated with the registry changes for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Re-disable RDP if not required and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect registry query and modification for RDP enablement |
