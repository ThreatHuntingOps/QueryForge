# Detection of Suspicious AutoIt Execution and Archive Downloads (Potential DarkCloud Stealer Infection)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AutoIt-DarkCloudStealer
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious execution of AutoIt-compiled executables (.exe) following the download of archive files (.rar, .zip) from potentially malicious file-sharing domains. Such activity is consistent with DarkCloud Stealer infection chains, which leverage phishing emails, malicious PDFs, and obfuscated AutoIt scripts to deliver infostealer payloads.

Detected behaviors include:

- Download of archive files (.rar, .zip) to user download directories from file-sharing services
- Execution of AutoIt-compiled executables with obfuscated or suspicious command lines
- Correlated DNS requests to known file-sharing domains

These techniques are commonly associated with initial access, payload delivery, and credential theft in targeted phishing campaigns.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                             |
|------------------------------|--------------|--------------|-----------------------------------------------------------|
| TA0001 - Initial Access       | T1566.001    | —            | Phishing: Spearphishing Attachment                        |
| TA0002 - Execution           | T1203        | —            | Exploitation for Client Execution (Malicious PDF)         |
| TA0002 - Execution           | T1059.005    | —            | Command and Scripting Interpreter: AutoIt                 |
| TA0005 - Defense Evasion     | T1027        | —            | Obfuscated Files or Information                           |
| TA0010 - Exfiltration        | T1105        | —            | Ingress Tool Transfer                                     |

---

## Hunt Query Logic

This query identifies suspicious AutoIt-compiled executable executions that are correlated with recent archive downloads from file-sharing domains:

- **DnsRequest Event:** Identifies DNS requests to known file-sharing domains commonly used to host malicious payloads.
- **FileWritten Event:** Detects downloaded archive files (.rar, .zip) written to typical user download directories.
- **ProcessRollup2 Event:** Captures execution of AutoIt-compiled executables, indicative of malicious payload execution.
- **Joins:** Events are joined to correlate DNS requests, file downloads, and subsequent suspicious process executions on the same host.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName="ProcessRollup2" 
| ImageFileName=/autoit.*\.exe/i OR CommandLine=/autoit.*\.exe/i 
| join( 
    {#event_simpleName="FileWritten" 
     | TargetFileName=/\.rar$|\.zip$/i 
     | FilePath=/C:\\Users\\.*|CSIDL_PROFILE\Downloads\.*/ 
    } 
    , field=aid 
    , key=aid 
    , include=[TargetFileName, FilePath] 
) 
| join( 
    {#event_simpleName="DnsRequest" 
     | DomainName=/fileshare|filetransfer|dropboxusercontent|onedrive|drive\.google|mega\.nz/i 
    } 
    , field=TargetProcessId 
    , key=TargetProcessId 
    , include=[DomainName] 
) 
| groupBy([aid, ComputerName], limit=max, function=collect([DomainName, TargetFileName, FilePath, ImageFileName, CommandLine])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2   | Process             | Process Creation       |
| Falcon       | N/A              | FileWritten      | File                | File Creation          |
| Falcon       | N/A              | DnsRequest       | Network             | DNS Request            |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute downloaded files.
- **Required Artifacts:** Archive files, process execution logs, DNS request logs.

---

## Considerations

- Investigate the source and contents of downloaded archive files.
- Validate the legitimacy of AutoIt-compiled executables and their command lines.
- Review DNS requests for connections to suspicious file-sharing domains.
- Correlate activity with known DarkCloud Stealer indicators or threat intelligence.

---

## False Positives

False positives may occur if:

- Users legitimately download and execute AutoIt scripts from trusted sources.
- Internal tools or automation leverage AutoIt for benign purposes.
- File-sharing services are used for legitimate business operations.

---

## Recommended Response Actions

1. Investigate the downloaded archive files and their origin.
2. Analyze the executed AutoIt-compiled executables for malicious behavior.
3. Review command-line arguments and process ancestry for signs of obfuscation or credential theft.
4. Monitor for data exfiltration or C2 communications.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [Unit 42: DarkCloud Stealer and Obfuscated AutoIt Scripting](https://unit42.paloaltonetworks.com/darkcloud-stealer-and-obfuscated-autoit-scripting/)
- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: T1059.005 – Command and Scripting Interpreter: AutoIt](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-19 | Initial Detection | Created hunt query to detect suspicious AutoIt execution and archive downloads related to DarkCloud Stealer |
