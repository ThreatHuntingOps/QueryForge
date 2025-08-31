# Correlate Malicious Batch File Creation with New User Account Creation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-BatchUserPersistence
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with automated persistence mechanisms. It identifies when a suspicious batch file (e.g., `u1.bat`) is created in the Atlassian Confluence program directory and is closely followed by the creation or modification of a user account (e.g., `noname`, `Crackenn`). This pattern is strongly associated with attacker automation for establishing persistence and privilege escalation following exploitation.

Detected behaviors include:

- Creation of a suspicious batch file (`u1.bat`) in `C:\Program Files\Atlassian\Confluence\`
- Creation or modification of a user account (e.g., `noname`, `Crackenn`) via security events (Event IDs: 4720, 4722, 4738, 4724, 4741)
- Correlation of these events by process context, indicating automated persistence setup

Such activity is a strong indicator of attacker persistence and privilege escalation following exploitation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence         | T1059       | —            | Command and Scripting Interpreter             |
| TA0003 - Persistence         | T1136       | —            | Create Account                                |
| TA0004 - Privilege Escalation| T1078       | —            | Valid Accounts                                |

---

## Hunt Query Logic

This query identifies when a suspicious batch file is created in the Confluence directory and is closely followed by the creation or modification of a user account. This sequence is a strong indicator of automated persistence and privilege escalation.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: batch file creation in Confluence directory    
#event_simpleName=FileCreate    
| FileName="u1.bat"    
| FilePath=/C:\\Program Files\\Atlassian\\Confluence\\u1\.bat/i    
| join(    
  {    
    // Inner query: user account creation/modification events    
    #event_simpleName=SecurityEvent    
    | (EventID=4720 or EventID=4722 or EventID=4738 or EventID=4724 or EventID=4741)    
    | TargetUserName=/noname|Crackenn/i    
  }    
  , field=TargetProcessId // FileCreate's TargetProcessId    
  , key=ContextProcessId  // SecurityEvent's ContextProcessId    
  , include=[EventID, TargetUserName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FilePath, FileName, EventID, TargetUserName])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | FileCreate         | File                | File Creation          |
| Falcon       | 4720,4722,4738,4724,4741 | SecurityEvent | Account            | Account Creation/Modification |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and write files as the NetworkService user and create or modify user accounts.
- **Required Artifacts:** File creation logs, security event logs, process context correlation.

---

## Considerations

- Validate the context of the batch file and user account creation to reduce false positives.
- Confirm that the batch file and user account creation are not part of legitimate administrative or support activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately deploy batch files and create user accounts for maintenance or automation in the Confluence directory.
- Internal scripts or monitoring tools use similar patterns for updates or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious batch file and user account creation.
3. Review all processes associated with the batch file and user account for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK: T1136 – Create Account](https://attack.mitre.org/techniques/T1136/)
- [MITRE ATT&CK: T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-23 | Initial Detection | Created hunt query to detect batch file and user account creation for persistence |
