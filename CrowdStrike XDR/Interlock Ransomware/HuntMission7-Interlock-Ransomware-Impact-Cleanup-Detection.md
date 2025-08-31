# Detection of Interlock Ransomware Impact and Cleanup Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Interlock-Impact-Cleanup
- **Operating Systems:** WindowsEndpoint, WindowsServer, Linux
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the execution of suspicious 64-bit `conhost.exe` encryptors, DLL-based cleanup activity (e.g., `tmp41.wasd` via `rundll32.exe`), and the presence of ransomware artifacts such as encrypted file extensions (`.interlock`, `.1nt3rlock`) and ransom notes (`!README!.txt`). These behaviors are associated with Interlock ransomware’s impact, data destruction, and double-extortion tactics. Detected behaviors include:

- Execution of suspicious `conhost.exe` processes (potentially masquerading as legitimate Windows binaries)
- DLL-based cleanup or artifact removal via `rundll32.exe` (e.g., `tmp41.wasd`)
- Creation or presence of ransomware file artifacts: encrypted extensions or ransom notes

These techniques are commonly used by Interlock ransomware operators to maximize impact, evade detection, and facilitate extortion.

---

## ATT&CK Mapping

| Tactic                | Technique   | Subtechnique | Technique Name                                         |
|-----------------------|-------------|--------------|-------------------------------------------------------|
| TA0040 - Impact       | T1486       | —            | Data Encrypted for Impact                             |
| TA0005 - Defense Evasion | T1036.005| —            | Masquerading: Match Legitimate Name or Location       |
| TA0005 - Defense Evasion | T1218.011| —            | Signed Binary Proxy Execution: Rundll32               |
| TA0005 - Defense Evasion | T1070.004| —            | Indicator Removal on Host: File Deletion              |
| TA0010 - Exfiltration | T1657       | —            | Data Manipulation                                     |

---

## Hunt Query Logic

This query identifies suspicious process and file events by looking for:

- Execution of `conhost.exe` (potentially a ransomware encryptor)
- Execution of `rundll32.exe` with command lines referencing `tmp41.wasd` (DLL-based cleanup)
- File events involving encrypted extensions (`.interlock`, `.1nt3rlock`) or ransom notes (`!README!.txt`)

These patterns are indicative of ransomware impact, cleanup, and artifact creation.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// title=Interlock Ransomware and Suspicious Process/File Activity  
// description=Detects suspicious conhost.exe execution, DLL cleanup via rundll32.exe, and ransomware file artifacts (encrypted extensions or ransom note) on Windows and Linux systems.

#event_simpleName=ProcessRollup2 OR event_simpleName=FileRollup2  
| ( (Platform = "Windows" OR Platform = "Linux") AND (
      (event_simpleName=ProcessRollup2 AND FileName = /conhost\.exe/i)
      OR (event_simpleName=ProcessRollup2 AND FileName = /rundll32\.exe/i AND CommandLine = "*tmp41.wasd*")
      OR (event_simpleName=FileRollup2 AND (
            FileName = "*.interlock*" OR
            FileName = "*.1nt3rlock*" OR
            FileName = "!__README__!.txt"
         ))
    )
  )  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute processes and modify or create files.
- **Required Artifacts:** Process creation logs, file creation/modification logs, and command-line arguments.

---

## Considerations

- Review the process and file events for legitimacy and context.
- Correlate with user activity, endpoint alerts, and ransomware threat intelligence.
- Investigate the presence of encrypted files and ransom notes for signs of ransomware impact.
- Validate if `conhost.exe` or `rundll32.exe` executions are legitimate or part of ransomware activity.

---

## False Positives

False positives may occur if:

- Legitimate administrative or cleanup scripts use similar file or process names.
- Security tools or IT staff perform file cleanup or use DLLs with similar naming conventions.

---

## Recommended Response Actions

1. Investigate the process and file events for intent and legitimacy.
2. Analyze encrypted files and ransom notes for ransomware indicators.
3. Review user activity and system logs for signs of ransomware execution or cleanup.
4. Isolate affected endpoints if ransomware impact is confirmed.
5. Block or monitor suspicious process and file activity related to Interlock ransomware.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK: T1218.011 – Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK: T1070.004 – Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004/)
- [MITRE ATT&CK: T1657 – Data Manipulation](https://attack.mitre.org/techniques/T1657/)
- [Unit 42: Interlock Ransomware Analysis](https://unit42.paloaltonetworks.com/interlock-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-23 | Initial Detection | Created hunt query to detect Interlock ransomware impact and cleanup activity               |
