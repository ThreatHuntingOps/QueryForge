# Detection of PowerShell Base64 Decoding and Payload Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-PowerShell-Base64PayloadExecution
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt identifies suspicious PowerShell activity that decodes Base64-encoded strings and writes the decoded content to disk. This behavior is consistent with multi-stage malware operations where PowerShell is used to download and then execute an obfuscated second-stage payload.

Key indicators include:
- Execution of `powershell.exe` with `FromBase64String` in the command line.
- Writing decoded content to locations such as `Temp` or `AppData`.
- Use of file output commands like `Write` or `Out-File`.

These behaviors often follow an initial infection stage and signal active payload decryption and staging.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                            |
|-------------------------------|------------|--------------|-----------------------------------------------------------|
| TA0002 - Execution            | T1059.001  | —            | Command and Scripting Interpreter: PowerShell             |
| TA0011 - Command and Control  | T1105      | —            | Ingress Tool Transfer                                     |

---

## Hunt Query Logic

This query focuses on identifying PowerShell-based decoding of Base64-encoded strings followed by file writing behavior, typical of malware unpacking or staging steps.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/ProcessRollup2|ProcessCreation/  
| (FileName = "powershell.exe")  
| (CommandLine = "*FromBase64String*")  
| (CommandLine = "*Temp*" OR CommandLine = "*AppData*")  
| (CommandLine = "*Write*" OR CommandLine = "*Out-File*")
```

---

## Data Sources

| Log Provider | Event ID | Event Name        | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|-------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2     | Process              | Process Creation        |

---

## Execution Requirements

- **Required Permissions:** Standard user permissions to execute PowerShell scripts.
- **Required Artifacts:** Command-line parameters and process execution data.

---

## Considerations

- Analyze the decoded payloads for malicious indicators or executable content.
- Review execution sequence to determine whether the PowerShell activity is linked to earlier phishing or download behavior.
- Validate whether the writing actions involve temporary scripting or scheduled task creation.

---

## False Positives

False positives may occur if:
- Admin or automation scripts legitimately decode and write Base64 content.
- Security or forensics tools use similar logic for detection or logging purposes.

---

## Recommended Response Actions

1. Analyze the Base64-decoded content for malicious payloads.
2. Review preceding download activity for additional context.
3. Isolate the affected endpoint if payload is confirmed malicious.
4. Trace lateral movement or privilege escalation attempts stemming from decoded payload.

---

## References

- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Cascading Shadows: An Attack Chain Approach to Avoid Detection and Complicate Analysis](https://unit42.paloaltonetworks.com/phishing-campaign-with-complex-attack-chain/#new_tab)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-28 | Initial Detection | Created hunt query for detection of PowerShell base64 decoding and payload execution      |
