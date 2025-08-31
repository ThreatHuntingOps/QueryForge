# Detection of Malicious PDF Downloads and AutoIt Execution (Potential Phishing and Malware Delivery via File-Sharing Services)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-PDF-AutoIt-FileSharing
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious activity involving the opening of PDF files (often via Adobe Reader or similar viewers), followed by downloads of archive files (.rar, .zip, .001) from known file-sharing services, and subsequent execution of AutoIt-compiled executables. This sequence is characteristic of phishing campaigns that use fake Adobe Flash Player update prompts to deliver malware payloads such as DarkCloud Stealer.

Detected behaviors include:

- Opening of PDF files via Adobe Reader or similar processes
- DNS requests to suspicious or malicious file-sharing domains (e.g., catbox.moe, dropboxusercontent, onedrive, mega.nz)
- Download of archive files to user download directories
- Execution of AutoIt-compiled executables following the download

These techniques are commonly associated with initial access, payload delivery, and credential theft in targeted phishing campaigns.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                             |
|------------------------------|--------------|--------------|-----------------------------------------------------------|
| TA0001 - Initial Access       | T1566.001    | —            | Phishing: Spearphishing Attachment                        |
| TA0002 - Execution           | T1203        | —            | Exploitation for Client Execution (Fake Adobe Flash prompt)|
| TA0010 - Exfiltration        | T1105        | —            | Ingress Tool Transfer                                     |
| TA0002 - Execution           | T1059.005    | —            | Command and Scripting Interpreter: AutoIt                 |
| TA0005 - Defense Evasion     | T1027        | —            | Obfuscated Files or Information                           |

---

## Hunt Query Logic

This query identifies a multi-stage attack chain:

- **Initial PDF Execution:** Detects PDF files opened via Adobe Reader or similar PDF viewers, potentially triggering malicious pop-ups.
- **DNS Requests:** Identifies DNS lookups to known malicious or suspicious file-sharing domains (including the specific domain "catbox.moe" from provided intelligence).
- **File Downloads:** Detects downloaded archive files (.rar, .zip, .001) written to typical user download directories.
- **AutoIt Execution:** Captures execution of AutoIt compiled executables, indicative of malicious payload execution.
- **Joins:** Events are correlated by aid (agent ID) and TargetProcessId to ensure accurate tracking of the attack chain from PDF opening through payload execution.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Detect PDF opening followed by suspicious downloads from file-sharing services and AutoIt execution

#event_simpleName="ProcessRollup2" 
| ImageFileName=/\.exe$|\.pdf$/i 
| CommandLine=/Adobe|Reader|AcroRd32\.exe/i 
| join( 
    {#event_simpleName="DnsRequest" 
     | DomainName=/catbox\.moe|fileshare|filetransfer|dropboxusercontent|onedrive|drive\.google|mega\.nz/i 
     | join( 
         {#event_simpleName="FileWritten" 
          | TargetFileName=/\.rar$|\.zip$|\.001$/i 
          | FilePath=/C:\\Users\\.*|CSIDL_PROFILE\\Downloads\\.*/
          | join( 
              {#event_simpleName="ProcessRollup2" 
               | ImageFileName=/autoit.*\.exe/i OR CommandLine=/autoit.*\.exe/i 
              } 
              , field=aid 
              , key=aid 
              , include=[ImageFileName, CommandLine] 
            ) 
         } 
         , field=aid 
         , key=aid 
         , include=[TargetFileName, FilePath, ImageFileName, CommandLine] 
       ) 
    } 
    , field=TargetProcessId 
    , key=TargetProcessId 
    , include=[DomainName, TargetFileName, FilePath, ImageFileName, CommandLine] 
) 
| groupBy([aid, ComputerName], limit=max, function=collect([ImageFileName, CommandLine, DomainName, TargetFileName, FilePath])) 
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

- **Required Permissions:** User or attacker must be able to open PDF files and execute downloaded files.
- **Required Artifacts:** PDF files, archive files, process execution logs, DNS request logs.

---

## Considerations

- Investigate the source and contents of downloaded PDF and archive files.
- Validate the legitimacy of AutoIt-compiled executables and their command lines.
- Review DNS requests for connections to suspicious file-sharing domains.
- Correlate activity with known phishing and malware delivery indicators.

---

## False Positives

False positives may occur if:

- Users legitimately download and open PDF or archive files from trusted sources.
- Internal tools or automation leverage AutoIt for benign purposes.
- File-sharing services are used for legitimate business operations.

---

## Recommended Response Actions

1. Investigate the downloaded PDF and archive files and their origin.
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
| 1.0     | 2025-05-19 | Initial Detection | Created hunt query to detect malicious PDF downloads and AutoIt execution from file-sharing services |
