# Detection of Python Package Downloads from Cloudflare Tunnel Domains

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-CloudflarePythonZip
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the download of ZIP files (notably `cam.zip`, `FTSP.zip`, or similar) from `trycloudflare.com` domains using common download utilities such as `curl.exe`, `wget.exe`, `powershell.exe`, or `certutil.exe`. Cloudflare tunnels are often abused by threat actors to deliver Python payloads or other malware, leveraging the trusted Cloudflare infrastructure to evade network defenses. The presence of ZIP file downloads from these domains is a strong indicator of suspicious or malicious activity, especially in environments where such downloads are not expected.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                                  |
| TA0011 - Command and Control | T1071.001   | —            | Application Layer Protocol: Web Protocols              |

---

## Hunt Query Logic

This query identifies suspicious downloads of ZIP files from Cloudflare tunnel domains:

- The process name is `curl.exe`, `wget.exe`, `powershell.exe`, or `certutil.exe` (case-insensitive)
- The command line includes both `trycloudflare.com` and a reference to a `.zip` file

Such patterns are frequently observed in malware delivery and initial access scenarios involving Python-based payloads or other malicious archives.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = /curl\.exe/i OR FileName = /wget\.exe/i OR FileName = /powershell\.exe/i OR FileName = /certutil\.exe/i)    
| CommandLine = "*trycloudflare.com*" AND CommandLine = "*.zip*"   
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute download utilities.
- **Required Artifacts:** Process creation logs, command-line arguments, network activity logs.

---

## Considerations

- Investigate the ZIP file's contents and origin for malicious payloads.
- Review the parent process to determine how the download was initiated.
- Correlate with network logs to identify the full scope of the download and any subsequent activity.
- Check for additional files or payloads extracted from the ZIP archive.

---

## False Positives

False positives are rare but may occur if:

- Legitimate administrative or automation scripts download ZIP files from Cloudflare tunnels for valid reasons (uncommon in most environments).

---

## Recommended Response Actions

1. Investigate the ZIP file and its source.
2. Analyze command-line arguments for suspicious download activity.
3. Review network logs for connections to untrusted or external domains.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized payloads or scripts.

---

## References

- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-01 | Initial Detection | Created hunt query to detect Python package downloads from Cloudflare tunnel domains        |
