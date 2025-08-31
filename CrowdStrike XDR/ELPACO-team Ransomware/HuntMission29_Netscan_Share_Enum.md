# Correlate netscan.exe Drop with Network and Share Enumeration

## Severity or Impact of the Detected Behavior
- **Risk Score:** 93
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-NetscanShareEnum
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with network and share enumeration using `netscan.exe`. It identifies when `netscan.exe` is dropped on a user’s Desktop and then used to scan the network and enumerate SMB shares, including the creation of the `delete.me` file (a known artifact of share enumeration) and the triggering of Security event 5145.

Detected behaviors include:

- Creation of `netscan.exe` on a user’s Desktop
- Subsequent creation of `delete.me` (share enumeration artifact)
- Correlation of these events by process context, indicating network and share enumeration

Such activity is a strong indicator of network reconnaissance and lateral movement preparation by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery           | T1135       | —            | Network Share Discovery                       |
| TA0007 - Discovery           | T1046       | —            | Network Service Discovery                     |
| TA0007 - Discovery           | T1016       | —            | System Network Configuration Discovery        |

---

## Hunt Query Logic

This query identifies when `netscan.exe` is dropped on a user’s Desktop and then used to scan the network and enumerate SMB shares, as evidenced by the creation of `delete.me`.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: netscan.exe file creation on Desktop    
#event_simpleName=FileCreate    
| FileName="netscan.exe"    
| FilePath=/C:\\Users\\[^\\]+\\Desktop\\netscan\.exe/i     
| join(    
  {    
    // Inner query: file creation of delete.me (share enumeration artifact)    
    #event_simpleName=FileCreate    
    | FileName="delete.me"    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[FileName, FilePath]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, FilePath]))    
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | FileCreate             | File                | File Creation          |
| Windows      | 5145             | Security Event         | File Share          | Share Enumeration      |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to drop and execute files on the user’s Desktop.
- **Required Artifacts:** File creation logs, process context correlation, Security event 5145.

---

## Considerations

- Validate the context of the netscan and delete.me file creation to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate network scanning or share enumeration.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized network scanning is detected.
2. Investigate the source and intent of the netscan and delete.me file creation.
3. Review all processes associated with the tool and artifacts for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1135 – Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
- [MITRE ATT&CK: T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK: T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect netscan drop and share enumeration |
