# Detection of spinstall0.aspx Webshell Creation by Known SHA256 Hash

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-spinstall0-Webshell-SHA256
- **Operating Systems:** WindowsServer, SharePoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects the creation of the `spinstall0.aspx` webshell on SharePoint servers by matching its known SHA256 hash. The presence of this file, especially with the specific hash, is a strong indicator of successful exploitation and webshell deployment by threat actors. This detection is crucial for identifying post-exploitation persistence and command execution capabilities on compromised servers.

Detected behaviors include:

- Creation of a file named `spinstall0.aspx` with SHA256 hash `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514`
- Associated process and command line information for further investigation

These patterns are indicative of webshell deployment and potential remote access.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Persistence         | T1505.003   | —            | Server Software Component: Web Shell           |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies webshell creation by looking for:

- File creation events for `spinstall0.aspx`
- SHA256 hash matching the known malicious value
- Relevant metadata such as timestamp, hostname, file path, and process details

These patterns are indicative of successful webshell deployment on SharePoint servers.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Detection of spinstall0.aspx Webshell Creation by Known SHA256 Hash
// Description: Detects the creation of the spinstall0.aspx webshell using its known SHA256 hash.
// MITRE ATT&CK TTP IDs: T1505.003, T1105

dataset = xdr_data   
| filter event_type = ENUM.FILE 
| filter action_file_name = "spinstall0.aspx"  
| filter action_file_sha256 = "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514" 
| fields event_timestamp, agent_hostname, action_file_name, action_file_path, action_file_sha256, actor_process_image_name, actor_process_command_line  
```

---

## Data Sources

| Log Provider   | Event Name   | ATT&CK Data Source | ATT&CK Data Component |
|---------------|--------------|--------------------|-----------------------|
| Cortex XSIAM  | xdr_data     | File               | File Creation         |

---

## Execution Requirements

- **Required Permissions:** Ability to collect and analyze file creation logs from SharePoint servers.
- **Required Artifacts:** File creation event logs, file name, file path, SHA256 hash, process and command line details.

---

## Considerations

- Review the process and command line responsible for creating the webshell.
- Correlate with network and authentication logs for signs of initial access or lateral movement.
- Investigate any follow-on activity from the same host or user account.
- Validate if the SharePoint instance is patched for known vulnerabilities.

---

## False Positives

False positives are extremely unlikely due to the specificity of the file name and hash combination.

---

## Recommended Response Actions

1. Immediately isolate the affected server.
2. Investigate the process and user responsible for the webshell creation.
3. Remove the webshell and perform a full forensic analysis.
4. Apply security patches for any relevant SharePoint vulnerabilities.
5. Monitor for additional suspicious activity or persistence mechanisms.

---

## References

- [MITRE ATT&CK: T1505.003 – Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-21 | Initial Detection | Created hunt query to detect spinstall0.aspx webshell creation by known SHA256 hash |
