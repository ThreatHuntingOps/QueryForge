# Detection of In-Memory PE/NET Module Execution via Donut Loader

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-DonutLoaderPE
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects instances where `python.exe` spawns short-lived, high-entropy child processes such as `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wscript.exe`, or `cscript.exe` from suspicious user profile subdirectories (e.g., `Contacts`, `Extracted`, `Print`). This behavior is strongly associated with in-memory PE/.NET module execution via Donut Loader, a technique used by advanced threat actors to evade disk-based detection and execute payloads directly in memory. The combination of process ancestry, file path, and short process duration is a high-confidence indicator of malicious activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1059.005   | —            | Command and Scripting Interpreter: Visual Basic        |
| TA0005 - Defense Evasion     | T1218       | —            | Signed Binary Proxy Execution                          |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                                      |
| TA0005 - Defense Evasion     | T1027       | —            | Obfuscated Files or Information                        |

---

## Hunt Query Logic

This query identifies suspicious in-memory PE/NET module execution via Donut Loader:

- The parent process is `python.exe` (case-insensitive)
- The child process is `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wscript.exe`, or `cscript.exe` (case-insensitive)
- The file path includes `\Users\<username>\Contacts\`, `\Users\<username>\Extracted\`, or `\Users\<username>\Print\`
- The process duration is less than 120 seconds

Such patterns are rarely seen in legitimate workflows and are highly indicative of advanced in-memory payload delivery.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (ParentBaseFileName = /python\.exe/i)    
| (FileName = /rundll32\.exe/i OR FileName = /regsvr32\.exe/i OR FileName = /mshta\.exe/i OR FileName = /wscript\.exe/i OR FileName = /cscript\.exe/i)    
| (FilePath = "*\\Users\\*\\Contacts\\*" OR FilePath = "*\\Users\\*\\Extracted\\*" OR FilePath = "*\\Users\\*\\Print\\*")    
| Duration < 120
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute Python scripts and spawn PE/NET modules from user profile subdirectories.
- **Required Artifacts:** Process creation logs, parent-child process relationships, file paths, process duration.

---

## Considerations

- Investigate the parent Python script for Donut Loader or in-memory execution logic.
- Review the spawned process for injected code or unusual behavior.
- Correlate with other endpoint activity for signs of persistence or privilege escalation.
- Check for additional suspicious process creation events linked to these subdirectories.

---

## False Positives

False positives are extremely rare but may occur if:

- Legitimate automation or testing scripts use Python to launch these processes from user profile subdirectories (uncommon in most environments).

---

## Recommended Response Actions

1. Investigate the parent Python script or process.
2. Analyze the spawned process for signs of in-memory execution or malicious activity.
3. Review system and security logs for additional suspicious process creation events.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized scripts or payloads from these directories.

---

## References

- [MITRE ATT&CK: T1059.005 – Command and Scripting Interpreter: Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK: T1218 – Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Donut Loader: In-Memory Payload Delivery](https://github.com/TheWover/donut)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-02 | Initial Detection | Created hunt query to detect in-memory PE/NET module execution via Donut Loader            |
