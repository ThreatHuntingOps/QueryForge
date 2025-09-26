# AdaptixC2 C2 Communication Patterns Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85 (AdaptixC2 beaconing with non-standard ports)  
- **Severity:** High  

## Analytics Metadata
- **ID:** CorrelationRule-Network-AdaptixC2-C2-Beaconing  
- **Operating Systems:** WindowsEndpoint, WindowsServer, Linux  
- **False Positive Rate:** Low (repeated connections to suspicious ports with RFC1918 overlap)  

---

## Analytics

This correlation rule detects **command-and-control (C2) beaconing behavior associated with AdaptixC2**.  

Detected behaviors include:  

- **Non-standard HTTPS ports:** 4443 and high ports >8000 commonly used by AdaptixC2.  
- **Beacon-style traffic patterns:** repeated connections (3+) to the same IP:port pair.  
- **C2 staging infrastructure:** commodity VPS or compromised hosts with unusual port configurations.  
- **RFC1918 overlap patterns:** internal/private IP ranges sometimes observed with redirectors or pivots.  
- **Persistent connection attempts:** indicating established C2 channels rather than benign single connections.  

Detection requires **multiple connections to the same destination** to isolate persistent beaconing behavior and reduce false positives.

---

## ATT&CK Mapping

| Tactic              | Technique | Subtechnique | Technique Name                                    |
|---------------------|-----------|--------------|---------------------------------------------------|
| Command and Control | T1071     | T1071.001    | Application Layer Protocol: Web Protocols        |
| Command and Control | T1571     | -            | Non-Standard Port                                 |
| Exfiltration        | T1041     | -            | Exfiltration Over C2 Channel                      |
| Command and Control | T1568     | -            | Dynamic Resolution (VPS/redirectors with varying infra) |

---

## Query Logic

This analytic correlates **suspicious outbound network connections with beaconing patterns**.  
It prioritizes signals with:  

- Non-standard ports (4443, 8443, >8000) + repeated connections.  
- RFC1918 IP ranges indicating potential redirector/pivot activity.  
- Connection frequency indicating persistent C2 rather than benign traffic.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
config case_sensitive = false  
| dataset = xdr_data  
| filter event_type = NETWORK  
| filter dst_action_external_port in (443, 4443, 8443) or dst_action_external_port > 8000  
| filter action_network_protocol = ENUM.TCP  
| alter detection_name = "AdaptixC2 C2 Communication Pattern",  
       attack_technique = "T1071.001 - Web Protocols",  
       is_suspicious_port = if(dst_action_external_port = 4443, "yes", "no"),  
       is_high_port = if(dst_action_external_port > 8000, "yes", "no") 
| filter dst_actor_remote_ip ~= "172.16.*" or dst_actor_remote_ip ~= "10.*" or dst_actor_remote_ip ~= "192.168.*" or is_suspicious_port = "yes" 
| alter connection_pattern = concat(dst_actor_remote_ip, ":", to_string(dst_action_external_port)) 
| comp count() as connection_count by agent_hostname, connection_pattern, _time  
| filter connection_count >= 3  
| alter detection_name = "AdaptixC2 Beaconing Pattern" 
| fields _time, agent_hostname, connection_pattern, connection_count, detection_name 
| sort desc connection_count
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component       |
|----------------|------------|--------------------|-----------------------------|
| Cortex XSIAM   | xdr_data   | Network Traffic    | Network Connection Creation |

---

## Execution Requirements  
- **Required Permissions:** Network-level visibility; no host permissions required.  
- **Required Artifacts:** Network connection telemetry.  

---

## Considerations  
- AdaptixC2 commonly uses port 4443 instead of standard 443 for HTTPS C2.  
- High ports (>8000) are frequently leveraged for evasion.  
- RFC1918 overlap may indicate redirector infrastructure or internal pivoting.  

---

## False Positives  
- Legitimate applications using non-standard HTTPS ports (rare in enterprise environments).  
- VPN or proxy solutions with custom port configurations.  
- Internal applications communicating over high ports repeatedly.  

---

## Recommended Response Actions  
1. **Block suspicious IP:port combinations** at network perimeter.  
2. **Isolate affected systems** showing beaconing behavior.  
3. **Analyze network traffic** for payload content and C2 commands.  
4. **Hunt for additional compromised systems** communicating with same infrastructure.  
5. **Correlate with threat intelligence** to identify known AdaptixC2 infrastructure.  
6. **Implement DNS sinkholing** for identified C2 domains.  

---

## References  
- [MITRE ATT&CK: T1071.001 – Web Protocols](https://attack.mitre.org/techniques/T1071/001/)  
- [MITRE ATT&CK: T1571 – Non-Standard Port](https://attack.mitre.org/techniques/T1571/)  
- [MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)  
- [MITRE ATT&CK: T1568 – Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)  

---

## Version History  

| Version | Date       | Impact                         | Notes                                                        |
|---------|------------|--------------------------------|--------------------------------------------------------------|
| 1.0     | 2025-09-26 | Initial Detection Contribution | Added correlation for AdaptixC2 C2 beaconing patterns       |
