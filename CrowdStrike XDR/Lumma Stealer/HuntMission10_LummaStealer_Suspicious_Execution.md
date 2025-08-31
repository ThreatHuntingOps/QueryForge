
# Detection of Lumma Stealer Suspicious File Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-LummaSuspiciousExecution
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects execution of suspicious files commonly associated with Lumma Stealer malware. Lumma Stealer disguises its payloads using legitimate-sounding names such as “captcha,” “verification,” or “installer,” tricking users into executing them. These files often reside in user-accessible directories like `Users`, `ProgramData`, or temporary system folders.

Detection indicators include:

- File names that mimic installers or verification tools.
- Execution from common staging locations.
- Execution via Windows Command Shell (`cmd`, `bat`, etc.).

Such behaviors are often linked to initial infection vectors, social engineering lures, and post-download execution of malware.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                          |
|------------------------------|------------|---------------|---------------------------------------------------------|
| TA0002 - Execution            | T1204.002 | —             | User Execution: Malicious File                          |
| TA0005 - Defense Evasion      | T1036.005 | —             | Masquerading: Match Legitimate Name or Location         |
| TA0002 - Execution            | T1059.003 | —             | Command and Scripting Interpreter: Windows Command Shell |

---

## Hunt Query Logic

This query identifies execution of suspicious files based on naming patterns and execution paths that are typical of Lumma Stealer payloads.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 
| FileName=/.*(captcha|verification|update|installer|setup).*\.(exe|scr|bat|cmd)/i       
| (FilePath="*\\Users\\*" OR FilePath="*\\ProgramData\\*" OR FilePath="*\\Windows\\Temp\\*")   
| CommandLine = "C:\\*" 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User must have permission to execute binaries.
- **Required Artifacts:** Malicious payloads staged in accessible directories.

---

## Considerations

- Validate the hash and origin of the executable file.
- Check if the file was downloaded from a suspicious source or linked to phishing.
- Correlate with other alerts or telemetry like network activity or registry modifications.

---

## False Positives

False positives may occur if:

- Internal tools use similar naming conventions.
- Legitimate setup or update tools are misclassified.

---

## Recommended Response Actions

1. Quarantine the suspicious executable.
2. Conduct forensic review of parent process and user actions.
3. Investigate file origin and integrity.
4. Review system for additional malware indicators.
5. Apply endpoint isolation if required.

---

## References

- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [Lumma Stealer – Tracking distribution channels](https://securelist.com/lumma-fake-captcha-attacks-analysis/116274/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-25 | Initial Detection | Created hunt query to detect suspicious file executions mimicking installers and verifications |
