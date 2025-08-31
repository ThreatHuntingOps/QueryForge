
# Detection of Suspicious MSHTA Execution (JavaScript-based Infection Chain)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MSHTA-JS-InfectionChain
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious use of `mshta.exe` to execute JavaScript embedded within files disguised as media files (such as `.mp3`, `.mp4`, `.png`, `.jpg`, `.jpeg`). This technique is leveraged by malware families like Lumma Stealer to initiate multi-stage infection chains. Detected behaviors include:

- Execution of `mshta.exe` with command lines referencing media file extensions
- Use of URLs or UNC/local file paths in the command line
- Potential delivery of remote or obfuscated JavaScript payloads

Such activity is strongly associated with initial access, execution, and defense evasion techniques in modern malware campaigns.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution            | T1218.005   | —            | Signed Binary Proxy Execution: Mshta                   |
| TA0002 - Execution            | T1203       | —            | Exploitation for Client Execution                      |
| TA0005 - Defense Evasion      | T1027       | —            | Obfuscated Files or Information                        |

---

## Hunt Query Logic

This query identifies suspicious `mshta.exe` executions that match multiple indicators:

- Command lines referencing media file extensions (e.g., `.mp3`, `.mp4`, `.png`, `.jpg`, `.jpeg`)
- Command lines containing URLs (http/https), UNC paths (\), or user profile paths (`C:\Users\`)

These patterns are commonly seen in JavaScript-based infection chains, where adversaries disguise payloads as benign media files to evade detection.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 
| FileName="mshta.exe"    
| in(field="CommandLine", values=["*.mp3*", "*.mp4*", "*.png*", "*.jpg*", "*.jpeg*"]) 
| in(field="CommandLine", values=["http*", "https*", "\\*", "*:\Users\*"])
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute `mshta.exe`.
- **Required Artifacts:** Process creation logs, command-line arguments.

---

## Considerations

- Investigate the source and content of the referenced media files.
- Validate if the command line includes remote URLs or suspicious local/UNC paths.
- Review parent process and user context for signs of phishing or drive-by compromise.
- Correlate activity with known threat intelligence or IOCs related to Lumma Stealer or similar malware.

---

## False Positives

False positives may occur if:

- Legitimate administrative scripts use `mshta.exe` with media file references for automation.
- Internal tools or legacy applications leverage `mshta.exe` for benign purposes.

---

## Recommended Response Actions

1. Investigate the referenced media file and its source.
2. Analyze the command-line arguments for obfuscated or encoded JavaScript.
3. Review network logs for suspicious outbound connections initiated by `mshta.exe`.
4. Isolate affected systems if malicious activity is confirmed.
5. Hunt for additional signs of multi-stage infection or lateral movement.

---

## References

- [MITRE ATT&CK: T1218.005 – Signed Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [MITRE ATT&CK: T1203 – Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Lumma Stealer – Tracking distribution channels](https://securelist.com/lumma-fake-captcha-attacks-analysis/116274/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-25 | Initial Detection | Created hunt query to detect suspicious MSHTA executions with JavaScript-based infection chain |
