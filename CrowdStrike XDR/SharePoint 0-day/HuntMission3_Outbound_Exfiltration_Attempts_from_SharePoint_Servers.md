# Detection of Outbound Exfiltration Attempts from SharePoint Servers

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-OutboundExfil
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects outbound network connections from SharePoint servers (specifically from `w3wp.exe`, `spinstall0.aspx`, or `spkeydump.aspx`) to suspicious or non-corporate IP addresses. Such activity is a strong indicator of data exfiltration, particularly of cryptographic keys or other sensitive information, and is often associated with webshell or post-exploitation activity. The query excludes connections to known internal or reserved subnets and focuses on high-numbered ports or cases where the remote port is not specified, which are common in exfiltration scenarios.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0010 - Exfiltration         | T1041       | —            | Exfiltration Over C2 Channel                           |
| TA0011 - Command and Control  | T1071       | —            | Application Layer Protocol                             |
| TA0010 - Exfiltration         | T1567       | —            | Exfiltration Over Web Service                          |

---

## Hunt Query Logic

This query identifies outbound network connections initiated by SharePoint worker processes or known webshell files. It joins process creation events with network activity, filtering out connections to internal or reserved IP ranges (replace `<internal_subnets>` with your organization’s actual internal IP ranges). The focus is on connections to external IPs, especially on high-numbered ports, which may indicate exfiltration of sensitive data.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2
| (FileName = "w3wp.exe" OR FileName = "spinstall0.aspx" OR FileName = "spkeydump.aspx")
| join(
    {
        #event_simpleName=/DnsRequest|NetworkConnectIP4|NetworkReceiveAcceptIP4/
        | !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/32", "169.254.0.0/16", "0.0.0.0/32"])  // Replace with <internal_subnets>
        | (RemotePort >= 1024 OR isnull(RemotePort))
    }
    , field=ProcessId
    , key=ContextProcessId
    , include=[RemoteAddressIP4, RemotePort, DomainName]
)
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |
| Falcon       | DnsRequest               | Network            | DNS Request           |
| Falcon       | NetworkConnectIP4        | Network            | Network Connection    |
| Falcon       | NetworkReceiveAcceptIP4  | Network            | Network Traffic       |

---

## Execution Requirements

- **Required Permissions:** Attacker must have achieved code execution within the SharePoint process context and be able to initiate outbound network connections.
- **Required Artifacts:** Process creation logs, network connection logs, DNS request logs.

---

## Considerations

- Replace `<internal_subnets>` in the query with your organization’s actual internal IP ranges to avoid false positives.
- Investigate the destination IP addresses and domains for reputation and threat intelligence context.
- Correlate with recent suspicious process or file creation events on the SharePoint server.
- Review the volume and timing of outbound connections for signs of automated exfiltration.

---

## False Positives

False positives may occur if:

- SharePoint servers legitimately communicate with external services for updates, telemetry, or integrations.
- Security or monitoring tools initiate outbound connections as part of their normal operation.

Validate the destination, context, and associated process activity to reduce false positives.

---

## Recommended Response Actions

1. Investigate the destination IP address and domain for malicious reputation or known threat actor infrastructure.
2. Analyze the associated process and command-line arguments for evidence of exfiltration or webshell activity.
3. Review network logs for additional suspicious outbound connections from the same server.
4. Isolate the affected SharePoint server if malicious exfiltration is confirmed.
5. Patch and harden SharePoint and underlying systems to prevent further compromise.

---

## References

- [MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK: T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK: T1567 – Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-22 | Initial Detection | Created hunt query to detect outbound exfiltration attempts from SharePoint servers         |
