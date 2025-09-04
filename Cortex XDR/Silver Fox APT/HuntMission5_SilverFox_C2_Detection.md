# Silver Fox APT - Encrypted C2 Communications Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-SilverFox-C2
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt identifies command and control communications associated with Silver Fox APT operations. It detects network connections to China-based infrastructure and the characteristic anti-analysis check to ip-api.com. The query also identifies ValleyRAT payload downloads and C2 beacon patterns, focusing on encrypted communications and suspicious network behaviors from compromised systems. Detected behaviors include:

- Anti-analysis geolocation checks to ip-api.com from US-based destinations
- Outbound connections to China on ports 80, 443, 8080, 8443
- Suspicious outbound connections from RuntimeBroker.exe in non-standard paths

These techniques are associated with encrypted C2 channels, web protocol usage, system location discovery, and ingress tool transfer.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0011 - Command and Control | T1071       | T1071.001    | Application Layer Protocol: Web Protocols     |
| TA0011 - Command and Control | T1573       |              | Encrypted Channel                             |
| TA0007 - Discovery           | T1614       |              | System Location Discovery                     |
| TA0011 - Command and Control | T1105       |              | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies C2 communications by looking for:

- DNS queries to ip-api.com from US destinations for anti-analysis
- Network connections to China on common web/C2 ports
- Outbound traffic from masqueraded RuntimeBroker.exe processes

These patterns are indicative of Silver Fox APT's encrypted C2 and payload delivery mechanisms.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
config case_sensitive = false 
| dataset = xdr_data 
| filter (   
    // Detect anti-analysis geolocation checks  
    (dst_action_country = "United States" and dns_query_name contains "ip-api.com") or  
    // Detect connections to China-based C2 infrastructure  
    (dst_action_country = "China" and action_remote_port in (80, 443, 8080, 8443)) or  
    // Detect suspicious outbound connections from RuntimeBroker.exe  
    (actor_process_image_name = "RuntimeBroker.exe" and   
     actor_process_image_path !~= ".*\System32\.*" and  
     action_direction = ENUM.OUTBOUND)  
)  
| fields event_timestamp, actor_process_image_name, actor_process_image_path,  
         action_remote_ip, dst_action_country, action_remote_port, dns_query_name,  
         action_direction, causality_actor_process_image_sha256  
| sort desc event_timestamp  
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Network Traffic     | Network Connection Creation |
| Cortex XSIAM|    xdr_data       | DNS                 | DNS Query                |

---

## Execution Requirements

- **Required Permissions:** Network access to perform outbound connections and DNS queries.
- **Required Artifacts:** Network traffic logs, DNS query logs, process execution logs.

---

## Considerations

- Review the destination IPs and domains for known malicious infrastructure.
- Correlate with process activity to confirm masquerading or suspicious execution.
- Investigate geolocation checks for anti-analysis intent.
- Validate connections to China-based IPs against threat intelligence feeds.

---

## False Positives

False positives may occur if:

- Legitimate network traffic to China for business purposes.
- Benign geolocation services usage.
- Legitimate RuntimeBroker.exe processes with outbound connections.

---

## Recommended Response Actions

1. Investigate the network connections and DNS queries for malicious intent.
2. Analyze associated processes for signs of compromise.
3. Block suspicious IPs and domains if confirmed malicious.
4. Isolate affected endpoints if C2 activity is detected.
5. Monitor for encrypted channels and payload downloads.

---

## References

- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK: T1573 – Encrypted Channel](https://attack.mitre.org/techniques/T1573/)
- [MITRE ATT&CK: T1614 – System Location Discovery](https://attack.mitre.org/techniques/T1614/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-09-04 | Initial Detection | Created hunt query to detect Silver Fox APT C2 communications                             |
