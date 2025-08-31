# Detection of WebSocket Upgrade Attempts to Unusual Hosts and Ports (VShell C2 Behavior)

## Hunt Analytics Metadata

- **ID:** `HuntQuery-Linux-WebSocket-C2-Behavioral`
- **Operating Systems:** `LinuxEndpoint`, `LinuxServer`
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects behavioral indicators of WebSocket-based command and control (C2) communications, focusing on the VShell malware as observed in the SNOWLIGHT campaign by UNC5174. The implant attempts to upgrade HTTP connections to WebSocket using the `Upgrade: websocket` and `Connection: Upgrade` headers, often over port 8443 to suspicious hosts such as `vs.gooogleasia.com`. This technique enables encrypted, stealthy C2 channels that evade traditional detection.

Detection logic is based on behavioral patterns, not static IOCs, to identify stealthy C2 activity. Key behaviors include:

- Outbound connections to port 8443 on suspicious or lookalike domains
- HTTP requests containing WebSocket upgrade headers
- Command lines referencing WebSocket activity or specific GET requests

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0011 - Command and Control | T1071.001   | —            | Application Layer Protocol: Web Protocols              |
| TA0011 - Command and Control | T1095       | —            | Non-Application Layer Protocol                         |
| TA0011 - Command and Control | T1043       | —            | Commonly Used Port Abuse                               |
| TA0011 - Command and Control | T1027       | —            | Obfuscated/Encrypted Command and Control               |
| TA0011 - Command and Control | T1071.004   | —            | Application Layer Protocol: DNS                        |

---

## Hunt Query Logic

This query identifies suspicious WebSocket upgrade attempts and C2 beaconing:

- Outbound connections to port 8443 on `vs.gooogleasia.com` or similar domains
- HTTP requests with `Upgrade: websocket` and `Connection: Upgrade` headers
- Command lines referencing WebSocket activity or specific GET requests

These patterns are indicative of malware using WebSocket as a C2 channel.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=NetworkConnectionInfo OR event_simpleName=NetworkHttpRequestInfo  
| (RemotePort = 8443 AND (RemoteAddress = "vs.gooogleasia.com" OR RemoteAddress CONTAINS "gooogleasia.com"))  
| (HttpRequestHeaders CONTAINS "Upgrade: websocket" AND HttpRequestHeaders CONTAINS "Connection: Upgrade")  
| (CommandLine=/.*GET \/w HTTP\/1.1.*/i OR CommandLine=/.*websocket.*/i) 
```

---

## Data Sources

| Log Provider | Event ID | Event Name              | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|-------------------------|---------------------|------------------------|
| Falcon       | N/A      | NetworkConnectionInfo   | Network             | Network Connection     |
| Falcon       | N/A      | NetworkHttpRequestInfo  | Network             | HTTP Request           |

---

## Execution Requirements

- **Required Permissions:** Attacker or user must be able to initiate outbound HTTP/WebSocket connections.
- **Required Artifacts:** Network connection logs, HTTP request logs, process command lines.

---

## Considerations

- Review the context of outbound WebSocket upgrade attempts, especially to suspicious or lookalike domains.
- Investigate the parent process and user context for privilege escalation or lateral movement.
- Correlate with threat intelligence for domain enrichment.
- Examine for additional persistence or lateral movement mechanisms.

---

## False Positives

False positives may occur if:

- Legitimate applications use WebSocket for real-time communication over port 8443.
- Internal testing or red team activity mimics WebSocket C2 behavior.

---

## Recommended Response Actions

1. Investigate the process and user responsible for the suspicious WebSocket activity.
2. Review the destination domains and IPs for known malicious infrastructure.
3. Analyze the process and network traffic for C2 or exfiltration behavior.
4. Check for additional persistence or lateral movement mechanisms.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK: T1095 – Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
- [MITRE ATT&CK: T1043 – Commonly Used Port Abuse](https://attack.mitre.org/techniques/T1043/)
- [MITRE ATT&CK: T1027 – Obfuscated/Encrypted Command and Control](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: T1071.004 – Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [UNC5174’s evolution in China’s ongoing cyber warfare: From SNOWLIGHT to VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-21 | Initial Detection | Created hunt query to detect WebSocket C2 beaconing to suspicious hosts and ports (VShell) |
