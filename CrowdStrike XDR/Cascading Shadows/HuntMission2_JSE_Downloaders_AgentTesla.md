# Detection of JSE Downloaders Delivered via 7z Archives in Agent Tesla Campaign

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-7z-JSE-Downloader-AgentTesla
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium

---

## Hunt Analytics

This hunt identifies suspicious executions of JavaScript Encoded (`.jse`) files extracted from `.7z` archives that masquerade as legitimate documents. These `.jse` files act as downloaders by invoking PowerShell commands to retrieve remote payloads.

Key detection patterns include:
- `.jse` filenames beginning with "doc" (e.g., `doc1234.jse`) to imitate document files.
- `.jse` scripts launching PowerShell containing web-download functions such as `Invoke-WebRequest`, `DownloadString`, or `IEX`.
- Scripts originating from common user-controlled locations like `AppData`, `Temp`, or `Downloads`.
- Execution via trusted scripting hosts (`wscript.exe` or `cscript.exe`).

These activities align with early-stage behaviors of Agent Tesla phishing campaigns.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                            |
|-------------------------------|------------|--------------|-----------------------------------------------------------|
| TA0001 - Initial Access       | T1566.001  | —            | Phishing: Spearphishing Attachment                        |
| TA0002 - Execution            | T1204.002  | —            | User Execution: Malicious File                            |
| TA0002 - Execution            | T1059.007  | —            | Command and Scripting Interpreter: JavaScript             |
| TA0002 - Execution            | T1059.001  | —            | Command and Scripting Interpreter: PowerShell             |
| TA0011 - Command and Control  | T1105      | —            | Ingress Tool Transfer                                     |

---

## Hunt Query Logic

This query focuses on detecting `.jse` files starting with "doc" that trigger PowerShell-based web download functions, ensuring early identification of phishing downloaders before full malware deployment.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/ProcessRollup2|ProcessCreation/  
| (FileName = /\.jse$/i)  
| (CommandLine = "*powershell*" AND (CommandLine = "*Invoke-WebRequest*" OR CommandLine = "*DownloadString*" OR CommandLine = "*IEX*"))  
| (ParentBaseFileName = "wscript.exe" OR ParentBaseFileName = "cscript.exe")  
| (FilePath = "*\\AppData\\*" OR FilePath = "*\\Temp\\*" OR FilePath = "*\\Downloads\\*")  
| (FileName = /doc.*\.jse/i)
```

---

## Data Sources

| Log Provider | Event ID | Event Name        | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|-------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2     | Process              | Process Creation        |

---

## Execution Requirements

- **Required Permissions:** Standard user permissions to extract archives and execute scripts.
- **Required Artifacts:** Process creation logs and command-line details.

---

## Considerations

- Investigate the originating email and attached `.7z` archive.
- Analyze the retrieved payloads for secondary stage malware indicators.
- Validate user intent when interacting with downloaded archives.

---

## False Positives

False positives may occur if:
- Internal scripts are legitimately distributed via `.7z` archives.
- Developers or IT admins execute test `.jse` scripts mimicking legitimate document names.

---

## Recommended Response Actions

1. Quarantine the suspicious `.jse` file and analyze its contents.
2. Trace downloaded payloads and inspect for Agent Tesla or other malware.
3. Monitor for additional lateral movement or credential access attempts.
4. Isolate compromised systems if malware infection is confirmed.

---

## References

- [MITRE ATT&CK: T1566.001 – Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1059.007 – JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Cascading Shadows: An Attack Chain Approach to Avoid Detection and Complicate Analysis](https://unit42.paloaltonetworks.com/phishing-campaign-with-complex-attack-chain/#new_tab)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-28 | Initial Detection | Created hunt query for detection of JSE downloaders delivered via phishing campaigns |
