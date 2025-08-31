# Correlate Metasploit Loader Process, DLL Drop, and Named Pipe Creation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 92
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MetasploitDLLPipe
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Metasploit post-exploitation activity. It identifies when a suspicious process (Metasploit loader) creates a randomized DLL in the NetworkService temporary directory and then creates a named pipe with the same base name as the DLL. This pattern is strongly associated with Metasploit's use of reflective DLL injection and named pipes for command and control (C2) or inter-process communication (IPC).

Detected behaviors include:

- Creation of a DLL with a randomized name in `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\`
- Creation of a named pipe (e.g., `\nbjlop`) by the same process, where the pipe name matches the DLL base name
- Correlation of these events by process context, indicating automated loader and C2/IPC setup

Such activity is a strong indicator of Metasploit post-exploitation, reflective DLL injection, and C2 channel establishment.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0004 - Privilege Escalation| T1055       | —            | Process Injection                             |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |
| TA0001 - Initial Access      | T1091       | —            | Replication Through Removable Media (Named Pipe for C2/IPC) |

---

## Hunt Query Logic

This query identifies when a suspicious DLL is created in the NetworkService temp directory and a named pipe with the same base name is created by the same process. This sequence is a strong indicator of Metasploit loader and C2/IPC activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=FileCreate
| FilePath=/C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\.*\\.dll/i
| join(
    {
        #event_simpleName=PipeCreated
        | PipeName=/\\\\[a-z]{6}/i
    }
    , field=TargetProcessId
    , key=ContextProcessId
    , include=PipeName
)
| groupBy([aid, ComputerName], limit=max, function=collect([FilePath, FileName, PipeName])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | FileCreate         | File                | File Creation          |
| Falcon       | N/A              | PipeCreated        | Named Pipe          | Named Pipe Creation    |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and create files and named pipes as the NetworkService user.
- **Required Artifacts:** File creation logs, named pipe creation logs, process context correlation.

---

## Considerations

- Validate the context of the DLL and named pipe creation to reduce false positives.
- Confirm that the DLL and pipe names are not part of legitimate administrative or update activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or automated tools legitimately create DLLs and named pipes with matching names in the temp directory.
- Internal scripts or monitoring tools use similar patterns for IPC or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious DLL and named pipe creation.
3. Review all processes associated with the DLL and pipe for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1091 – Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-23 | Initial Detection | Created hunt query to detect Metasploit loader DLL drop and named pipe creation |
