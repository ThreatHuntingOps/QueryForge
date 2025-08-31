# Detection of Suspicious Binary Associated with FakePenny Encryptor

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-FakePennyEncryptor
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects execution of suspicious binaries that are not widely seen in the environment and may be related to ransomware encryption operations, particularly those associated with FakePenny. The detection logic focuses on binaries named `encryptor.exe` or those executed with the `--encrypt` command-line argument, running from non-standard directories, and optionally matching known or unknown hashes. This is especially relevant if seen shortly after loader activity or in compromised environments.

Such behavior is indicative of ransomware activity, obfuscated file execution, and data encryption for impact.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell|
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                              |
| TA0005 - Defense Evasion     | T1027       | —            | Obfuscated Files or Information                        |

---

## Hunt Query Logic

This query identifies suspicious encryptor binary executions by detecting:

- Process file name matching `encryptor.exe` or command line containing `--encrypt`
- Execution from directories outside of standard locations (not in `C:\Program Files\*` or `C:\Windows\*`)
- Optionally, matches known or unknown hashes (SHA256 or MD5)

These patterns are commonly seen in ransomware attacks where custom or rare encryptor binaries are deployed for data encryption.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (FileName = /encryptor\.exe/i OR CommandLine = "*--encrypt*")  
| (FilePath != "C:\\Program Files\\*" AND FilePath != "C:\\Windows\\*")  
| (SHA256Hash = "*" OR MD5Hash = "*") // Add IOC hashes if known     
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute custom binaries.
- **Required Artifacts:** Process creation logs, file path information, hash values.

---

## Considerations

- Validate the file hash and signature of the detected binary against threat intelligence.
- Investigate the process lineage and timing relative to loader or initial access activity.
- Correlate with other endpoint or network alerts for signs of ransomware or encryption activity.

---

## False Positives

False positives may occur if:

- Legitimate software uses custom encryptor binaries for benign purposes outside standard directories.
- Security testing or red team activities mimic these behaviors.

---

## Recommended Response Actions

1. Isolate the affected endpoint if ransomware activity is confirmed.
2. Analyze the suspicious binary for malicious content or encryption routines.
3. Investigate user and process activity around the time of execution.
4. Initiate incident response and recovery procedures as appropriate.
5. Update detection rules and threat intelligence with new indicators as needed.

---

## References

- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks (Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-09 | Initial Detection | Created hunt query to detect suspicious binary associated with FakePenny encryptor          |
