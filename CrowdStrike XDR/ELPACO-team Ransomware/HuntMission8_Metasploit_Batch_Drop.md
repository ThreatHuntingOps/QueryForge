# Correlate Metasploit Loader Process with Batch File Creation in Confluence Directory

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MetasploitBatchDrop
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with Metasploit post-exploitation activity and potential persistence mechanisms. It identifies when a process (Metasploit loader) creates an executable in the NetworkService temp directory and then drops a batch file (e.g., `u1.bat`) in the Atlassian Confluence program directory. This pattern is strongly associated with attackers establishing persistence or automating post-exploitation actions via batch scripts.

Detected behaviors include:

- Creation of an executable by a Metasploit loader in `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\`
- Creation of a batch file (e.g., `u1.bat`) in `C:\Program Files\Atlassian\Confluence\`
- Correlation of these events by process context, indicating automated loader and persistence script deployment

Such activity is a strong indicator of attacker persistence setup or post-exploitation automation following exploitation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059       | —            | Command and Scripting Interpreter             |
| TA0003 - Persistence         | T1547       | —            | Boot or Logon Autostart Execution             |

---

## Hunt Query Logic

This query identifies when a process (Metasploit loader) creates an executable in the NetworkService temp directory and then drops a batch file in the Atlassian Confluence program directory. This sequence is a strong indicator of attacker persistence setup.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: process creation in temp directory (Metasploit loader)    
#event_simpleName=ProcessRollup2    
| FilePath=/C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\.*\.exe/i      
| join(    
  {    
    // Inner query: batch file creation by same process    
    #event_simpleName=FileCreate    
    | FileName=/.*\.bat/i    
    | FilePath=/C:\\Program Files\\Atlassian\\Confluence\\.*/     
  }    
  , field=TargetProcessId // ProcessRollup2's TargetProcessId    
  , key=ContextProcessId  // FileCreate's ContextProcessId    
  , include=[FilePath, FileName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FilePath, FileName])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A              | FileCreate         | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and write files as the NetworkService user and to the Confluence program directory.
- **Required Artifacts:** Process creation logs, file creation logs, process context correlation.

---

## Considerations

- Validate the context of the process and file creation to reduce false positives.
- Confirm that the batch file deployment is not part of legitimate administrative or support activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately deploy batch files for maintenance or automation in the Confluence directory.
- Internal scripts or monitoring tools use similar patterns for updates or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious process and batch file deployment.
3. Review all processes associated with the loader and batch file for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK: T1547 – Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-23 | Initial Detection | Created hunt query to detect Metasploit loader and batch file drop in Confluence directory |
