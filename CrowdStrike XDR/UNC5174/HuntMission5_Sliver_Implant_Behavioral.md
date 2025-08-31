# Detection of Suspicious Sliver Implant Activity Leveraging Encrypted C2 (Sliver)

## Hunt Analytics Metadata

- **ID:** `HuntQuery-Linux-Sliver-Implant-Behavioral`
- **Operating Systems:** `LinuxEndpoint`, `LinuxServer`
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects behavioral indicators of Sliver framework implants, such as the system_worker binary, which are commonly used by threat actors like UNC5174. These implants are typically Go-based, UPX-packed, and obfuscated with gobfuscate, and they leverage encrypted C2 channels (mTLS, HTTPS, WireGuard) to communicate with suspicious or lookalike domains (e.g., `mtls.sex666vr.com`, `https.sex666vr.com`, `wg.gooogleasia.com`).

The detection logic focuses on behavioral patterns rather than static IOCs, enabling the identification of new or modified Sliver variants. Key behaviors include:

- Use of encrypted protocols (HTTPS, TLS, WireGuard) for outbound connections
- Process or command-line artifacts referencing `system_worker` or `sliver`
- Go-based binaries with known obfuscation or packing characteristics
- Communication with suspicious or lookalike domains

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0011 - Command and Control | T1071.004   | —            | Application Layer Protocol: DNS                        |
| TA0011 - Command and Control | T1071.001   | —            | Application Layer Protocol: Web Protocols              |
| TA0010 - Exfiltration        | T1105       | —            | Ingress Tool Transfer                                  |
| TA0011 - Command and Control | T1573.002   | —            | Encrypted Channel: Asymmetric Cryptography (mTLS)      |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                                      |
| TA0005 - Defense Evasion     | T1027.002   | —            | Obfuscated Files or Information: Software Packing      |

---

## Hunt Query Logic

This query identifies suspicious network and process activity consistent with Sliver implant behavior:

- Outbound connections using encrypted protocols (HTTPS, TLS, WireGuard)
- Process creation or command lines referencing `system_worker` or `sliver`
- Go-based binaries with UPX/gobfuscate obfuscation and known hash patterns
- DNS or network connections to suspicious or lookalike domains

These patterns are indicative of Sliver C2 implants and their communication methods.

---

## Initial Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/NetworkConnectIP4|NetworkConnectIP6|DnsRequest|ProcessRollup2/ 
| (Protocol = "HTTPS" OR Protocol = "TLS" OR Protocol = "WireGuard") 
OR (CommandLine=/.*system_worker.*/i OR FileName=/.*system_worker.*/i) 
OR (CommandLine=/.*sliver.*/i OR CommandLine=/.*--mtls.*/i OR CommandLine=/.*--https.*/i OR CommandLine=/.*--wireguard.*/i) 
OR (FileName=/.*\.go.*/i AND (SHA256HashData=/21ccb25887ea.*/i OR SHA256HashData=/.*4c964db/))
```

## Refined Hunt Query Syntax

```fql
#event_simpleName=/NetworkConnectIP4|NetworkConnectIP6|DnsRequest|ProcessRollup2/ 
| (Protocol = "HTTPS" OR Protocol = "TLS" OR Protocol = "WireGuard") 
OR (CommandLine=/.*system_worker.*/i OR FileName=/.*system_worker.*/i) 
OR (CommandLine=/.*sliver.*/i OR CommandLine=/.*--mtls.*/i OR CommandLine=/.*--wireguard.*/i) 
OR (FileName=/.*\.go.*/i AND (SHA256HashData=/21ccb25887ea.*/i OR SHA256HashData=/.*4c964db/))
| CommandLine != "*/Princeton Dropbox/*"
| CommandLine != "*\\AppData\\Local\\GitHubDesktop\\*"
| CommandLine != "*CrowdStrike/*"
```


---

## Data Sources

| Log Provider | Event ID | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|--------------------|---------------------|------------------------|
| Falcon       | N/A      | NetworkConnectIP4  | Network             | Network Connection     |
| Falcon       | N/A      | NetworkConnectIP6  | Network             | Network Connection     |
| Falcon       | N/A      | DnsRequest         | Network             | DNS Query              |
| Falcon       | N/A      | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker or user must be able to execute Go-based binaries and initiate outbound encrypted network connections.
- **Required Artifacts:** Process creation logs, network connection logs, DNS queries, binary hashes.

---

## Considerations

- Review the context of encrypted outbound connections, especially to suspicious or lookalike domains.
- Investigate the origin and characteristics of Go-based binaries, including packing and obfuscation.
- Correlate with threat intelligence for domain and hash enrichment.
- Examine parent process and user context for privilege escalation or lateral movement.

---

## False Positives

False positives may occur if:

- Legitimate Go-based applications use encrypted protocols or similar command-line arguments.
- Security tools or monitoring agents are packed or obfuscated for protection.
- Internal testing or red team activity mimics Sliver implant behavior.

---

## Recommended Response Actions

1. Investigate the process and user responsible for the suspicious activity.
2. Review the destination domains and IPs for known malicious infrastructure.
3. Analyze the binary for UPX packing, gobfuscate obfuscation, and Sliver framework artifacts.
4. Check for additional persistence or lateral movement mechanisms.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1071.004 – Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1573.002 – Encrypted Channel: Asymmetric Cryptography (mTLS)](https://attack.mitre.org/techniques/T1573/002/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1027.002 – Obfuscated Files or Information: Software Packing](https://attack.mitre.org/techniques/T1027/002/)
- [Sliver C2 Framework](https://github.com/BishopFox/sliver)
- [UNC5174’s evolution in China’s ongoing cyber warfare: From SNOWLIGHT to VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-21 | Initial Detection | Created hunt query to detect behavioral Sliver implant activity leveraging encrypted C2    |
| 1.1     | 2025-04-23 | Refined Detection  | Adjusted the initial hunt query to filter out legitimate activity and reduce false positives  |
