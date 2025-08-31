# Detection of GET Requests to spinstall0.aspx Webshell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-spinstall0-Webshell-GET
- **Operating Systems:** WindowsServer, SharePoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects HTTP GET requests to the malicious `spinstall0.aspx` webshell on SharePoint servers. Such requests are typically used by attackers to interact with the webshell, often for the purpose of exfiltrating cryptographic secrets or executing remote commands. The presence of these requests is a strong indicator of post-exploitation activity and potential data theft.

Detected behaviors include:

- HTTP GET requests to `/ _layouts/15/spinstall0.aspx`
- Suspicious user agents or repeated access patterns

These patterns are indicative of webshell usage and exfiltration over a command and control (C2) channel.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0010 - Exfiltration        | T1041       | —            | Exfiltration Over C2 Channel                  |
| TA0008 - Persistence         | T1505.003   | —            | Server Software Component: Web Shell           |

---

## Hunt Query Logic

This query identifies webshell usage by looking for:

- Network events with HTTP GET requests to `/ _layouts/15/spinstall0.aspx`
- Relevant metadata such as timestamp, hostname, URL, HTTP method, and user agent

These patterns are indicative of attempts to interact with or exfiltrate data via the webshell.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Detection of GET Requests to spinstall0.aspx Webshell
// Description: Identifies HTTP GET requests to the malicious spinstall0.aspx file, which is used to exfiltrate cryptographic secrets.
// MITRE ATT&CK TTP IDs: T1041, T1505.003

dataset = xdr_data    
| filter event_type = ENUM.NETWORK  
| filter dst_action_url contains "/_layouts/15/spinstall0.aspx"    
| filter http_method = "GET"    
| fields event_timestamp, agent_hostname, dst_action_url, http_method, action_user_agent 
```

---

## Data Sources

| Log Provider   | Event Name   | ATT&CK Data Source | ATT&CK Data Component |
|---------------|--------------|--------------------|-----------------------|
| Cortex XSIAM  | xdr_data     | Network Traffic    | Web Request           |

---

## Execution Requirements

- **Required Permissions:** Ability to collect and analyze network traffic logs from SharePoint servers.
- **Required Artifacts:** Network event logs, HTTP request metadata (method, URL, user agent).

---

## Considerations

- Review the source IP and user agent for known attacker infrastructure or automated tools.
- Correlate with file creation and process logs for evidence of webshell deployment.
- Investigate any follow-on activity from the same source, such as lateral movement or privilege escalation.
- Validate if the SharePoint instance is patched for known vulnerabilities.

---

## False Positives

False positives are extremely unlikely due to the specificity of the file path and method.

---

## Recommended Response Actions

1. Immediately isolate the affected server.
2. Investigate the source and intent of the GET request.
3. Remove the webshell and perform a full forensic analysis.
4. Apply security patches for any relevant SharePoint vulnerabilities.
5. Monitor for additional suspicious activity or persistence mechanisms.

---

## References

- [MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK: T1505.003 – Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-21 | Initial Detection | Created hunt query to detect GET requests to spinstall0.aspx webshell |
