# Detection of Python Executing Binary/Obfuscated Scripts from User Profile Subdirectories

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-PythonObfuscatedUserDirs
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects instances where `python.exe` executes `.py` files from suspicious user profile subdirectories such as `Contacts`, `Extracted`, or `Print`. These locations are rarely used for legitimate Python script execution and are often leveraged by threat actors to stage Kramer-obfuscated or otherwise malicious payloads. The presence of Python scripts in these directories is a strong indicator of compromise or post-exploitation activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1059.006   | —            | Command and Scripting Interpreter: Python              |
| TA0005 - Defense Evasion     | T1027       | —            | Obfuscated Files or Information                        |
| TA0003 - Persistence         | T1547.001   | —            | Registry Run Keys / Startup Folder                     |

---

## Hunt Query Logic

This query identifies suspicious executions of Python scripts from user profile subdirectories:

- The process name is `python.exe` (case-insensitive)
- The command line includes a path to `\Users\<username>\Contacts\`, `\Users\<username>\Extracted\`, or `\Users\<username>\Print\` ending in `.py`

Such patterns are rarely seen in legitimate workflows and are often associated with obfuscated or staged payloads.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = /python\.exe/i)    
| CommandLine = "*\\Users\\*\\Contacts\\*\\*.py*" OR CommandLine = "*\\Users\\*\\Extracted\\*\\*.py*" OR CommandLine = "*\\Users\\*\\Print\\*\\*.py*"
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute Python scripts from user profile subdirectories.
- **Required Artifacts:** Python scripts in Contacts, Extracted, or Print directories; process creation logs; command-line arguments.

---

## Considerations

- Investigate the Python script and its origin for obfuscation or malicious logic.
- Review the parent process to determine how the script was dropped or executed.
- Correlate with other endpoint activity for signs of lateral movement or persistence.
- Check for additional files or payloads staged in these directories.

---

## False Positives

False positives are rare but may occur if:

- Legitimate administrative or automation scripts are run from these directories (uncommon in most environments).

---

## Recommended Response Actions

1. Investigate the Python script and its source.
2. Analyze command-line arguments for suspicious or obfuscated code.
3. Review system and security logs for additional signs of compromise.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized scripts or payloads from these directories.

---

## References

- [MITRE ATT&CK: T1059.006 – Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: T1547.001 – Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-02 | Initial Detection | Created hunt query to detect Python executing binary/obfuscated scripts from user profile subdirectories |
