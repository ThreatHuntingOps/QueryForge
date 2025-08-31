# Detection of ZIP File Extraction to User Contacts Directory

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-ZipExtractContacts
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the extraction of ZIP files into the user's Contacts directory, an unusual location for legitimate software activity. Attackers may leverage this directory to stage payloads or evade detection, as it is rarely monitored and not commonly used by standard applications for file extraction. The use of utilities such as `powershell.exe`, `7z.exe`, `winrar.exe`, or `expand.exe` to extract files into this directory is a strong indicator of suspicious or malicious behavior.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0005 - Defense Evasion     | T1140       | —            | Deobfuscate/Decode Files or Information                |
| TA0005 - Defense Evasion     | T1036.005   | —            | Masquerading: Match Legitimate Name or Location        |

---

## Hunt Query Logic

This query identifies suspicious ZIP file extraction activity targeting the user's Contacts directory:

- The process name is `powershell.exe`, `7z.exe`, `winrar.exe`, or `expand.exe` (case-insensitive)
- The command line includes a path to `\Users\<username>\Contacts\`
- The command line includes extraction-related keywords such as `extract`, `unzip`, or `Expand-Archive`

Such patterns are rarely seen in legitimate workflows and are often associated with attempts to stage or hide malicious payloads.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = /powershell\.exe/i OR FileName = /7z\.exe/i OR FileName = /winrar\.exe/i OR FileName = /expand\.exe/i)    
| CommandLine = "*\\Users\\*\\Contacts\\*" AND (CommandLine = "*extract*" OR CommandLine = "*unzip*" OR CommandLine = "*Expand-Archive*")    
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute extraction utilities and write to the Contacts directory.
- **Required Artifacts:** Process creation logs, command-line arguments, extracted files in Contacts directory.

---

## Considerations

- Investigate the extracted files and their origin for malicious payloads.
- Review the parent process to determine how the extraction was initiated.
- Correlate with other endpoint activity for signs of lateral movement or persistence.
- Check for additional files or payloads staged in the Contacts directory.

---

## False Positives

False positives are rare but may occur if:

- Legitimate administrative or backup scripts extract files to the Contacts directory (uncommon in most environments).

---

## Recommended Response Actions

1. Investigate the extracted files and their source.
2. Analyze command-line arguments for suspicious extraction activity.
3. Review system and security logs for additional signs of compromise.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized payloads or scripts from the Contacts directory.

---

## References

- [MITRE ATT&CK: T1140 – Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-02 | Initial Detection | Created hunt query to detect ZIP file extraction to user Contacts directory                |
