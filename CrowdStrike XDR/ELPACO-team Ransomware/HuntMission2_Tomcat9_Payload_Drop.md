# Correlate tomcat9.exe Child Process with Suspicious Payload Drop in NetworkService Temp

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Tomcat9PayloadDrop
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors indicative of post-exploitation activity on Atlassian Confluence servers. Specifically, it identifies when `tomcat9.exe` spawns a suspicious process (such as `curl.exe` or a randomized loader), which subsequently drops a suspicious executable (e.g., `HAHLGiDDb.exe`) in the `NetworkService` temporary directory. This pattern is strongly associated with the delivery and staging of malicious payloads following successful exploitation, such as ransomware or remote access tools.

Detected behaviors include:

- `tomcat9.exe` spawning a suspicious process (e.g., `curl.exe`, or executables with randomized names)
- The spawned process creating an executable file in `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\`
- File names matching known or suspicious patterns (e.g., `HAHLGiDDb.exe` or other randomized `.exe` names)

Such activity is a strong indicator of malicious payload delivery and staging, often preceding further exploitation or ransomware deployment.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059       | 003          | Command and Scripting Interpreter: Windows Command Shell |
| TA0005 - Defense Evasion     | T1036       | 005          | Masquerading: Match Legitimate Name or Location |
| TA0009 - Collection          | T1119       | —            | Automated Collection                          |
| TA0007 - Discovery           | T1082       | —            | System Information Discovery                  |
| TA0001 - Initial Access      | T1190       | —            | Exploit Public-Facing Application             |

---

## Hunt Query Logic

This query identifies when `tomcat9.exe` spawns a suspicious process (such as `curl.exe` or a randomized loader), which then creates an executable file in the `NetworkService` temp directory. This sequence is a strong indicator of malicious payload delivery and staging.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: suspicious process spawned by tomcat9.exe    
#event_simpleName=ProcessRollup2    
| ParentBaseFileName="tomcat9.exe"    
| (FileName="curl.exe" or FileName="HAHLGiDDb.exe" or FileName=/[A-Za-z0-9]{8,}\.exe/i)    
| join(    
  {    
    // Inner query: file creation by same process in temp directory    
    #event_simpleName=FileCreate    
    | FilePath=/C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\.*\.exe/i    
  }    
  , field=TargetProcessId // ProcessRollup2's TargetProcessId    
  , key=ContextProcessId  // FileCreate's ContextProcessId    
  , include=[FilePath, FileName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([ParentBaseFileName, FileName, FilePath]))
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A              | FileCreate         | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as the tomcat9 process and write files to the NetworkService temp directory.
- **Required Artifacts:** Process creation logs, file creation logs, suspicious executable detection.

---

## Considerations

- Validate the context of the process and file creation to reduce false positives.
- Confirm that the file creation in the temp directory is not part of legitimate administrative or update activity.
- Review additional process and file activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or automated tools legitimately use `curl.exe` or similar utilities for updates or diagnostics.
- Internal scripts or monitoring tools create executables in the temp directory as part of normal operations.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious process and payload drop.
3. Review all processes spawned by `tomcat9.exe` for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-23 | Initial Detection | Created hunt query to detect suspicious payload drops by tomcat9.exe child processes |
