# Correlate netscan.exe Execution with SMB Share Access (Event 5145)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 92
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-NetscanSMB5145
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with network and share enumeration using `netscan.exe`. It identifies execution of `netscan.exe` followed by Security event 5145, indicating enumeration of SMB shares and access checks.

Detected behaviors include:

- Execution of `netscan.exe`
- Subsequent Security event 5145 (SMB share access)
- Correlation of these events by process context, indicating network and share enumeration

Such activity is a strong indicator of network reconnaissance and lateral movement preparation by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery           | T1135       | —            | Network Share Discovery                       |
| TA0007 - Discovery           | T1046       | —            | Network Service Discovery                     |

---

## Hunt Query Logic

This query identifies when `netscan.exe` is executed and is followed by Security event 5145, a strong indicator of SMB share enumeration and access checks.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: netscan.exe execution    
#event_simpleName=ProcessRollup2    
| FileName="netscan.exe"    
| join(    
  {    
    // Inner query: Security event 5145 (SMB share access)    
    #event_simpleName=SecurityEvent    
    | EventID=5145    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[EventID, ObjectName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, EventID, ObjectName]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Windows      | 5145             | Security Event         | File Share          | Share Enumeration      |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as netscan and access SMB shares.
- **Required Artifacts:** Process creation logs, Security event 5145, process context correlation.

---

## Considerations

- Validate the context of the netscan execution and SMB share access to reduce false positives.
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
2. Investigate the source and intent of the netscan execution and SMB share access.
3. Review all processes associated with the tool and events for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1135 – Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
- [MITRE ATT&CK: T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect netscan execution and SMB share access (5145) |
