# Detection of Known Malicious IPs Accessing SharePoint LAYOUTS

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-MaliciousIPs-LAYOUTS
- **Operating Systems:** WindowsServer, SharePoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects HTTP requests to SharePoint LAYOUTS endpoints (`/_layouts/15/` or `/_layouts/16/`) originating from IP addresses known to be associated with active exploit campaigns. These IPs have been identified through threat intelligence as sources of malicious activity targeting public-facing SharePoint servers. Monitoring and alerting on these connections can help identify early-stage exploitation attempts and prevent further compromise.

Detected behaviors include:

- HTTP requests to SharePoint LAYOUTS endpoints from known malicious IP addresses
- Potential reconnaissance, exploitation, or post-exploitation activity

These patterns are indicative of targeted attacks leveraging known infrastructure.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0001 - Initial Access       | T1190       | —            | Exploit Public-Facing Application             |
| TA0007 - Discovery           | T1589       | —            | Gather Victim Identity Information            |

---

## Hunt Query Logic

This query identifies exploit attempts by looking for:

- Network events with requests to SharePoint LAYOUTS paths
- Source IP address matching a list of known malicious IPs associated with exploit campaigns

These patterns are indicative of attempts to exploit SharePoint using attacker-controlled infrastructure.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Detection of Known Malicious IPs Accessing SharePoint LAYOUTS
// Description: Detects HTTP requests to SharePoint LAYOUTS from IP addresses associated with exploit campaigns.
// MITRE ATT&CK TTP IDs: T1190, T1589

dataset = xdr_data   
| filter event_type = ENUM.NETWORK  
| filter dst_action_url contains "/_layouts/15/" or dst_action_url contains "/_layouts/16/"    
| filter agent_ip_addresses in ("107.191.58.76", "104.238.159.149", "96.9.125.147", "103.186.30.186") 
| fields event_timestamp, agent_hostname , dst_action_url, http_method, http_referer, action_user_agent  
```

---

## Data Sources

| Log Provider   | Event Name   | ATT&CK Data Source | ATT&CK Data Component |
|---------------|--------------|--------------------|-----------------------|
| Cortex XSIAM  | xdr_data     | Network Traffic    | Web Request           |

---

## Execution Requirements

- **Required Permissions:** Ability to collect and analyze network traffic logs from SharePoint servers.
- **Required Artifacts:** Network event logs, HTTP request metadata (method, URL, referer, user agent, source IP).

---

## Considerations

- Review the context and frequency of requests from these IP addresses.
- Correlate with other indicators of compromise, such as suspicious user agents or authentication attempts.
- Investigate any follow-on activity from the same source, such as privilege escalation or lateral movement.
- Validate if the SharePoint instance is patched for known vulnerabilities.

---

## False Positives

False positives are highly unlikely but may occur if:

- The listed IP addresses are used by legitimate third-party services or security scanners (rare).

---

## Recommended Response Actions

1. Investigate the source and intent of the HTTP request.
2. Review SharePoint server logs for signs of exploitation or unauthorized changes.
3. Isolate affected servers if compromise is suspected.
4. Block or monitor traffic from the identified malicious IP addresses.
5. Apply security patches for any relevant SharePoint vulnerabilities.
6. Monitor for additional suspicious activity from the same source.

---

## References

- [MITRE ATT&CK: T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK: T1589 – Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-21 | Initial Detection | Created hunt query to detect known malicious IPs accessing SharePoint LAYOUTS |
