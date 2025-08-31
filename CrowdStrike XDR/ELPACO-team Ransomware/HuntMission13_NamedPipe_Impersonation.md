# Correlate DLL Drop and Named Pipe Creation for Named Pipe Impersonation (Metasploit)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-NamedPipeImpersonation
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Metasploit privilege escalation via Named Pipe Impersonation. It identifies when a DLL (e.g., `nbjlop.dll`) is dropped in the NetworkService temp directory and a named pipe with the same base name is created, indicating a likely attempt to impersonate a privileged token via named pipe manipulation.

Detected behaviors include:

- Creation of a DLL file with a randomized six-letter name in `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\`
- Creation of a named pipe (e.g., `\nbjlop`) with the same base name as the DLL
- Correlation of these events by process context, indicating automated loader and privilege escalation attempt

Such activity is a strong indicator of Metasploit post-exploitation and privilege escalation via named pipe impersonation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0004 - Privilege Escalation| T1134       | 001          | Access Token Manipulation: Token Impersonation/Theft |
| TA0004 - Privilege Escalation| T1055       | —            | Process Injection                             |
| TA0004 - Privilege Escalation| T1068       | —            | Exploitation for Privilege Escalation         |

---

## Hunt Query Logic

This query identifies when a DLL with a randomized six-letter name is dropped in the NetworkService temp directory and a named pipe with the same base name is created. This sequence is a strong indicator of named pipe impersonation and privilege escalation activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=FileCreate
| FileName=/[a-z]{6}\\.dll/i
| FilePath=/C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\[a-z]{6}\\.dll/i
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
- [MITRE ATT&CK: T1134.001 – Access Token Manipulation: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect DLL drop and named pipe creation for impersonation |
