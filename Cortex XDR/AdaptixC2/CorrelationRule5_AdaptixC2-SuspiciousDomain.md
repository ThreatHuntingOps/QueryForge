# AdaptixC2 Suspicious Domain Communication Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90 (repeated connections to suspicious domains/ports)  
- **Severity:** High  

## Analytics Metadata
- **ID:** CorrelationRule-Network-AdaptixC2-SuspiciousDomain  
- **Operating Systems:** WindowsEndpoint, WindowsServer, Linux  
- **False Positive Rate:** Low (requires ≥3 connections and suspicious domains/ports)  

---

## Analytics

This correlation rule detects **network traffic to suspicious domains and ports associated with AdaptixC2 command‑and‑control (C2) infrastructure**.  

Detected behaviors include:  
- **Non-standard HTTPS ports:** 4443 and alternate TLS ports (8080, 8443).  
- **Suspicious or malicious TLDs:** `.online`, `.tech`, `.live`, `.shop`, `.info`, `.art`, `.one`, etc.  
- **AdaptixC2-specific domain keywords:** e.g., `tech-system`, `protoflint`, `flareaxe`, `systemware`.  
- **Beaconing patterns:** ≥3 repeated connections from the same host to the same domain or IP.  

By requiring 3 or more connections, detection isolates **persistent C2 communication** and reduces noise from benign interactions.

---

## ATT&CK Mapping

| Tactic              | Technique | Subtechnique | Technique Name                                |
|---------------------|-----------|--------------|-----------------------------------------------|
| Command and Control | T1071     | T1071.001    | Application Layer Protocol: Web Protocols     |
| Command and Control | T1571     | -            | Non-Standard Port                             |
| Command and Control | T1568     | -            | Dynamic Resolution (malicious/adversary domains) |
| Command and Control | T1071     | T1071.004    | Application Layer Protocol: DNS               |

---

## Query Logic

This analytic correlates **outbound TCP connections to suspicious domains and ports commonly leveraged by AdaptixC2**.  
It prioritizes detection when:  
- Destination domain contains suspicious TLDs.  
- Destination domain contains known AdaptixC2 keywords.  
- Connections occur to non-standard ports (4443, 8080, 8443).  
- There are ≥3 connections, indicating beaconing.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
config case_sensitive = false   
| dataset = xdr_data   
| filter event_type = NETWORK   
| filter action_network_protocol = ENUM.TCP and dst_action_external_port in (443, 4443, 8080, 8443)   
| alter detection_name = "AdaptixC2 Suspicious Domain Communication",   
       attack_technique = "T1071.001 - Web Protocols",  
       has_suspicious_tld = if(dst_action_url contains ".online"   
                             or dst_action_url contains ".tech"   
                             or dst_action_url contains ".site"  
                             or dst_action_url contains ".cc"   
                             or dst_action_url contains ".bg"   
                             or dst_action_url contains ".com"   
                             or dst_action_url contains ".live"   
                             or dst_action_url contains ".shop"   
                             or dst_action_url contains ".info"   
                             or dst_action_url contains ".art"   
                             or dst_action_url contains ".one", "yes", "no"),   
       has_adaptix_keyword = if(dst_action_url contains "tech-system"   
                                or dst_action_url contains "protoflint"   
                                or dst_action_url contains "novelumbsasa"   
                                or dst_action_url contains "picasosoftai" 
                                or dst_action_url contains "dtt.alux" 
                                or dst_action_url contains "moldostonesupplies" 
                                or dst_action_url contains "x6iye" 
                                or dst_action_url contains "buenohuy" 
                                or dst_action_url contains "firetrue" 
                                or dst_action_url contains "lokipoki" 
                                or dst_action_url contains "mautau" 
                                or dst_action_url contains "muatay" 
                                or dst_action_url contains "nicepliced" 
                                or dst_action_url contains "nissi" 
                                or dst_action_url contains "veryspec" 
                                or dst_action_url contains "express1solutions"   
                                or dst_action_url contains "doamin"   
                                or dst_action_url contains "regonalone"   
                                or dst_action_url contains "iorestore", "yes", "no"),   
       non_standard_port = if(dst_action_external_port = 4443, "yes", "no")   
| filter has_suspicious_tld = "yes" or has_adaptix_keyword = "yes" or non_standard_port = "yes"   
| comp count() as connection_count by agent_hostname, dst_action_url, dst_action_external_port   
| filter connection_count >= 3   
| fields agent_hostname, dst_action_url, dst_action_external_port, connection_count  
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component     |
|----------------|------------|--------------------|---------------------------|
| Cortex XSIAM   | xdr_data   | Network Traffic    | Network Connection Creation |

---

## Execution Requirements  
- **Required Permissions:** Network-level visibility.  
- **Required Artifacts:** Network telemetry (domain, IP, port, protocol).  

---

## Considerations  
- Many benign services do not use listed TLDs or non-standard ports.  
- Detection tuned for persistence by requiring repeated connections.  

---

## False Positives  
- Could occur with legitimate services hosted on suspicious TLDs or custom TLS ports.  
- Noise reduced by requiring ≥3 repeated connections.  

---

## Recommended Response Actions  
1. **Blocklist suspicious domains** identified.  
2. **Isolate host** with repeated suspicious communications.  
3. **Gather packet captures** for forensic inspection.  
4. **Pivot threat hunt** across enterprise for same suspicious keywords/domains.  
5. **Engage DNS logs** to look for additional related domain resolutions.  

---

## References  
- [MITRE ATT&CK: T1071.001 – Web Protocols](https://attack.mitre.org/techniques/T1071/001/)  
- [MITRE ATT&CK: T1571 – Non‑Standard Port](https://attack.mitre.org/techniques/T1571/)  
- [MITRE ATT&CK: T1568 – Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)  
- [MITRE ATT&CK: T1071.004 – DNS](https://attack.mitre.org/techniques/T1071/004/)  

---

## Version History  

| Version | Date       | Impact                         | Notes                                                       |
|---------|------------|--------------------------------|-------------------------------------------------------------|
| 1.0     | 2025-09-26 | Initial Detection Contribution | Added correlation for AdaptixC2 suspicious domain/port communication |
