# Detection of FakePenny Ransom Note Drop

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-FakePennyRansomNote
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the creation of files resembling ransom notes left by the FakePenny ransomware. These notes may mimic prior campaigns (such as NotPetya) and are strong indicators of a ransomware infection in progress or a post-infection artifact. The detection logic focuses on the creation of files with common ransom note names in user, ProgramData, or root directories, and with a file size greater than 100 bytes to reduce noise from empty or placeholder files.

Such behavior is indicative of ransomware activity, data encryption for impact, and attempts to inhibit system recovery or exfiltrate data.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                              |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                                  |
| TA0040 - Impact              | T1490       | —            | Inhibit System Recovery                                |

---

## Hunt Query Logic

This query identifies suspicious ransom note file creation by detecting:

- File names matching common ransom note patterns (e.g., `README.txt`, `README.html`, `HOW_TO_DECRYPT.txt`, `FAKEPENNY_NOTE.txt`)
- File creation in user, ProgramData, or root directories
- File size greater than 100 bytes

These patterns are commonly seen in ransomware attacks where ransom notes are dropped as part of the infection process.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=FileWriteInfo  
| FileName = "README.txt" OR FileName = "README.html" OR FileName = "HOW_TO_DECRYPT.txt" OR FileName = "FAKEPENNY_NOTE.txt"  
| (FilePath = "C:\\Users\\*" OR FilePath = "C:\\ProgramData\\*" OR FilePath = "C:\\")  
| FileSize > 100  
```

---

## Data Sources

| Log Provider | Event ID | Event Name     | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|----------------|---------------------|------------------------|
| Falcon       | N/A      | FileWriteInfo  | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to write files to user, ProgramData, or root directories.
- **Required Artifacts:** File creation logs, file path and size information.

---

## Considerations

- Validate the contents of the detected ransom note files for known ransomware signatures or text.
- Investigate the process and user context responsible for file creation.
- Correlate with other endpoint or network alerts for signs of ransomware activity or data encryption.

---

## False Positives

False positives may occur if:

- Legitimate software or scripts create files with similar names for benign purposes.
- Security testing or red team activities mimic ransomware note drops.

---

## Recommended Response Actions

1. Isolate the affected endpoint if ransomware activity is confirmed.
2. Analyze the ransom note file contents for attribution and threat intelligence.
3. Investigate user and process activity around the time of file creation.
4. Initiate incident response and recovery procedures as appropriate.
5. Update detection rules and threat intelligence with new indicators as needed.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks (Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-09 | Initial Detection | Created hunt query to detect FakePenny ransom note file creation                            |
