# Detection of Trojanized PuTTY Execution via Suspicious File Paths and Arguments

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-TrojanizedPutty
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious executions of the `putty.exe` binary that may indicate the use of a trojanized PuTTY, as observed in Moonstone Sleet and similar operations. The detection focuses on PuTTY binaries launched from non-default file paths and with command-line arguments commonly associated with malicious activity, such as `-pw` (password flag), `-ssh`, or references to `url.txt` (which may be used to deliver embedded payloads).

Such behaviors are often linked to initial access, credential theft, and payload delivery by threat actors leveraging legitimate tools for malicious purposes.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                         |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell|
| TA0005 - Defense Evasion     | T1036.005   | —            | Masquerading: Match Legitimate Name or Location        |

---

## Hunt Query Logic

This query identifies suspicious `putty.exe` executions that match the following indicators:

- PuTTY binary executed from a non-default installation path
- Command-line arguments containing `-pw`, `-ssh`, or references to `url.txt`
- File name or original file name matching `putty.exe`

These patterns are commonly seen in attacks where legitimate tools are repurposed for credential theft or payload delivery.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (FileName = /putty\.exe/i OR OriginalFileName = /putty\.exe/i)  
| (FilePath != "C:\\Program Files\\PuTTY\\putty.exe" AND FilePath != "C:\\Program Files (x86)\\PuTTY\\putty.exe")  
| CommandLine = "*url.txt*" OR CommandLine = "*-pw*" OR CommandLine = "*-ssh*" 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PuTTY binaries.
- **Required Artifacts:** Process creation logs, command-line arguments, file path information.

---

## Considerations

- Validate the file hash and signature of the detected PuTTY binary.
- Investigate the source and integrity of any referenced `url.txt` files.
- Review user activity and context around the execution event.
- Correlate with other endpoint or network alerts for lateral movement or data exfiltration.

---

## False Positives

False positives may occur if:

- PuTTY is legitimately installed in a non-default location for operational reasons.
- System administrators or automation scripts use command-line arguments for valid remote access.
- Security testing or red team activities mimic these behaviors.

---

## Recommended Response Actions

1. Isolate the affected endpoint if malicious activity is confirmed.
2. Analyze the suspicious PuTTY binary for tampering or embedded payloads.
3. Review user and process activity around the time of execution.
4. Investigate any credential usage or exfiltration attempts.
5. Update detection rules and threat intelligence with new indicators as needed.

---

## References

- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks (Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-09 | Initial Detection | Created hunt query to detect trojanized PuTTY executions with suspicious arguments and paths |
