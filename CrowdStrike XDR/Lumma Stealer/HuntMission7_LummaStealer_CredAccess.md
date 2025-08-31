# Suspicious Access to Credential Stores or Password Files (Credential Theft Behavior)

## Metadata
**ID:** HuntQuery-CrowdStrike-LummaStealer-CredAccess  
**OS:** WindowsEndpoint, WindowsServer  
**FP Rate:** Medium  

---

## ATT&CK Tags

| Tactic                | Technique | Subtechnique | Technique Name                                    |
|----------------------|-----------|---------------|---------------------------------------------------|
| TA0006 - Credential Access | T1555     | 003           | Credentials from Password Stores: Web Browsers    |
| TA0007 - Discovery     | T1083     | -             | File and Directory Discovery                      |
| TA0006 - Credential Access | T1552     | -             | Unsecured Credentials                             |

---

## Utilized Data Sources

| Log Provider | Event ID | Event Name        | ATT&CK Data Source | ATT&CK Data Component     |
|--------------|----------|-------------------|---------------------|----------------------------|
| Falcon       | N/A      | FileAccessed      | File                | File Access                |
| Falcon       | N/A      | ProcessRollup2    | Process             | Process Execution          |

---

## Technical description of the attack
Lumma Stealer is a known infostealer malware that targets credential stores and browser login data following initial infection. It commonly attempts to access sensitive files such as Chrome's `Login Data`, Firefox profile databases, and Edge credential stores. These are high-value targets that may contain saved usernames, passwords, session tokens, or browser-stored credentials.

---

## Permission required to execute the technique
User (with access to browser or local app data)

---

## Detection description
This hunt detects access to known credential store paths across Chrome, Firefox, and Edge by potentially malicious processes such as `wscript.exe`, temporary script runners (`*.tmp`), or `.js` files. These patterns align with behavior observed in Lumma Stealer campaigns seeking credential theft post-compromise.

---

## Considerations
File access alone may not indicate compromise—correlate with process ancestry, file hashes, and execution context. Consider filtering known safe access (e.g., from legitimate password managers or backup agents).

---

## False Positives
Some enterprise tools (e.g., profile migration utilities, legitimate backup software) may access browser credential stores. Validate based on the initiating process and organizational software inventory.

---

## Suggested Response Actions
- Analyze and triage the accessing process for malicious indicators.
- Check for exfiltration activity or outbound connections.
- Isolate affected endpoint.
- Revoke or rotate credentials if theft is confirmed.
- Hunt across the environment for similar file access patterns.

---

## References
* [MITRE ATT&CK - T1555.003](https://attack.mitre.org/techniques/T1555/003/)
* [MITRE ATT&CK - T1083](https://attack.mitre.org/techniques/T1083/)
* [MITRE ATT&CK - T1552](https://attack.mitre.org/techniques/T1552/)
* [Threat actors using fake Chrome updates to deliver Lumma Stealer](https://security.microsoft.com/threatanalytics3/4aa69db9-9f04-46ca-b07f-c67f7105f61d/analystreport?tid=2ff60116-7431-425d-b5af-077d7791bda4&si_retry=1)

---

## Detection

**Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=FileAccessed OR event_simpleName=ProcessRollup2
| (FilePath=*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data*
   OR FilePath=*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*
   OR FilePath=*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data*)
| InitiatingProcessFileName=wscript.exe OR InitiatingProcessFileName=*.tmp OR *.js
```

---
## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2025-04-13| Initial Detection | Created hunt query to detect credential theft via browser login store access by Lumma Stealer and similar malware |
