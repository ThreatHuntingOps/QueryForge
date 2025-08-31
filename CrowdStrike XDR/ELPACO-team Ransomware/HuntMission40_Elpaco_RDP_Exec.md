# Correlate ELPACO-team Ransomware Drop via RDP and Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 99
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-ELPACO-RDP-Exec
- **Operating Systems:** WindowsServer, WindowsEndpoint, BackupServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with lateral ransomware deployment via RDP. It identifies when `ELPACO-team.exe` is dropped on a backup server (in `D:\Admin\`) via RDP (using the “noname” account), then executed, indicating lateral ransomware deployment and execution.

Detected behaviors include:

- File creation of `ELPACO-team.exe` in `D:\Admin\`
- Subsequent process creation of `ELPACO-team.exe` by the “noname” account
- Correlation of these events by process context, indicating lateral ransomware deployment and execution

Such activity is a strong indicator of data encryption for impact, ingress tool transfer, and lateral movement via RDP by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |
| TA0008 - Lateral Movement    | T1021       | 001          | Remote Services: Remote Desktop Protocol       |
| TA0009 - Collection          | T1105       | —            | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies when `ELPACO-team.exe` is dropped on a backup server via RDP and then executed by the “noname” account, a strong indicator of lateral ransomware deployment and execution.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: file creation of ELPACO-team.exe in D:\Admin\    
#event_simpleName=FileCreate    
| FileName="ELPACO-team.exe"    
| FilePath="D:\\Admin\\ELPACO-team.exe"    
| join(    
  {    
    // Inner query: process creation of ELPACO-team.exe    
    #event_simpleName=ProcessRollup2    
    | FileName="ELPACO-team.exe"    
    | UserName="noname"    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[FileName, UserName, CommandLine]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, FilePath, UserName, CommandLine])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | FileCreate             | File                | File Creation          |
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to transfer files via RDP and execute code as the “noname” account.
- **Required Artifacts:** File creation logs, process creation logs, process context correlation.

---

## Considerations

- Validate the context of the file transfer and ransomware execution to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate file transfers and testing with the “noname” account.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected backup server from the network if unauthorized ransomware deployment is detected.
2. Investigate the source and intent of the file transfer and ransomware execution.
3. Review all processes associated with the ransomware and user account for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-29 | Initial Detection | Created hunt query to detect ELPACO-team ransomware drop via RDP and execution |
