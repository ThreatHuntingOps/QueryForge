# Correlate Metasploit Loader Process with AnyDesk Drop in Confluence Directory

## Severity or Impact of the Detected Behavior
- **Risk Score:** 94
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MetasploitAnyDeskDrop
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Metasploit post-exploitation activity and attacker remote access setup. It identifies when a process (Metasploit loader) creates an executable in the NetworkService temp directory and then drops `AnyDesk.exe` in the Atlassian Confluence program directory. This pattern is strongly associated with attackers establishing persistent remote access via legitimate remote administration tools following successful exploitation.

Detected behaviors include:

- Creation of an executable by a Metasploit loader in `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\`
- Creation of `AnyDesk.exe` in `C:\Program Files\Atlassian\Confluence\`
- Correlation of these events by process context, indicating automated loader and remote access tool deployment

Such activity is a strong indicator of attacker remote access setup and persistence following exploitation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence         | T1133       | —            | External Remote Services                      |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |
| TA0002 - Execution           | T1059       | 003          | Command and Scripting Interpreter: Windows Command Shell |

---

## Hunt Query Logic

This query identifies when a process (Metasploit loader) creates an executable in the NetworkService temp directory and then drops `AnyDesk.exe` in the Atlassian Confluence program directory. This sequence is a strong indicator of attacker remote access setup.

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
    // Inner query: AnyDesk.exe file creation by same process    
    #event_simpleName=FileCreate    
    | FileName="AnyDesk.exe"    
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
- Confirm that the AnyDesk deployment is not part of legitimate administrative or support activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately deploy AnyDesk for remote support in the Confluence directory.
- Internal scripts or monitoring tools use similar patterns for updates or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious process and AnyDesk deployment.
3. Review all processes associated with the loader and AnyDesk for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1133 – External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-23 | Initial Detection | Created hunt query to detect Metasploit loader and AnyDesk drop in Confluence directory |
