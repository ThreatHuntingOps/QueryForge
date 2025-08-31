# Correlate Batch Script for Share Creation with Security Event 5142

## Severity or Impact of the Detected Behavior
- **Risk Score:** 92
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-BatchShare5142
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with SMB share creation via batch scripting. It identifies execution of a batch script (e.g., `share_setup.bat`) that creates a new SMB share (using `net share`), followed by Security Event 5142 indicating the share was created.

Detected behaviors include:

- Execution of a batch script (`*.bat`) with `net share` in the command line
- Subsequent Security Event 5142 (share creation)
- Correlation of these events by process context, indicating automated or scripted share creation

Such activity is a strong indicator of lateral movement preparation, ingress tool transfer, or data staging by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021       | 002          | Remote Services: SMB/Windows Admin Shares      |
| TA0009 - Collection          | T1105       | —            | Ingress Tool Transfer                         |
| TA0007 - Discovery           | T1135       | —            | Network Share Discovery                       |

---

## Hunt Query Logic

This query identifies when a batch script is used to create a new SMB share, as evidenced by Security Event 5142, a strong indicator of share creation and possible lateral movement or data staging.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: batch script execution (e.g., share_setup.bat)    
#event_simpleName=ProcessRollup2    
| FileName=/.*\.bat/i    
| CommandLine=/net share/i    
| join(    
  {    
    // Inner query: Security Event 5142 (share creation)    
    #event_simpleName=SecurityEvent    
    | EventID=5142    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[EventID, ShareName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, CommandLine, EventID, ShareName]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Windows      | 5142             | Security Event         | File Share          | Share Creation         |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute batch scripts and create SMB shares.
- **Required Artifacts:** Process creation logs, Security Event 5142, process context correlation.

---

## Considerations

- Validate the context of the batch script and share creation to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate share creation or automation.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized share creation is detected.
2. Investigate the source and intent of the batch script and share creation.
3. Review all processes associated with the script and share for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1135 – Network Share Discovery](https://attack.mitre.org/techniques/T1135/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-28 | Initial Detection | Created hunt query to detect batch script share creation and Security Event 5142 |
