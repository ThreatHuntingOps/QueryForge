# Detection of Sliver Command-and-Control via Web Protocols (slv.bin & sliver-client)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-SliverC2-WebProtocols
- **Operating Systems:** WindowsEndpoint, WindowsServer, LinuxEndpoint, LinuxServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects activity related to the Sliver C2 framework, focusing on its binaries such as `slv.bin` and `sliver-client_linux`. Sliver is a popular open-source C2 framework used by both red teams and threat actors, leveraging encrypted web protocols (HTTPS, mTLS, WireGuard) for command-and-control. Even when payloads are encrypted or obfuscated, the execution of Sliver client components and suspicious command-line usage are high-fidelity indicators of compromise. This detection aims to identify Sliver staging, execution, or operator interaction from compromised endpoints.

Key detection behaviors include:

- Execution of Sliver binaries (`slv.bin`, `sliver-client_linux`, `sliver.exe`)
- Suspicious command-line arguments indicating C2 communication (e.g., `--mtls`, `--http`, `--https`, `connect`, ports 443/8443)
- Use of encrypted or obfuscated payloads over web protocols

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0011 - Command and Control  | T1071.001   | —            | Application Layer Protocol: Web Protocols              |
| TA0011 - Command and Control  | T1090.001   | —            | Proxy: Internal Proxy                                  |
| TA0043 - Reconnaissance       | T1219       | —            | Remote Access Software                                 |
| TA0009 - Collection           | T1105       | —            | Ingress Tool Transfer                                  |
| TA0011 - Command and Control  | T1573.002   | —            | Encrypted Channel: Asymmetric Cryptography             |

---

## Hunt Query Logic

This query identifies suspicious executions of Sliver C2 client binaries and related command-line arguments:

- Process creation events for `slv.bin`, `sliver-client`, or `sliver-client_linux`
- Command lines containing C2-relevant flags (`--mtls`, `--http`, `--https`, `connect`, ports 443/8443)
- Image file names matching Sliver client binaries

These patterns are strong indicators of Sliver C2 staging or operator activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (FileName = /slv\.bin/i OR FileName = /sliver-client/i)  
| (CommandLine = "*sliver-client*" OR CommandLine = "*slv.bin*" 
OR CommandLine = "*--mtls*" OR CommandLine = "*--http*" OR CommandLine = "*--https*" 
OR CommandLine = "*connect*" AND (CommandLine = "*443*" OR CommandLine = "*8443*")) 
| (ImageFileName = "*sliver-client_linux*" OR ImageFileName = "*sliver.exe*") 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute binaries on the endpoint.
- **Required Artifacts:** Sliver client binaries, process creation logs, command-line arguments.

---

## Considerations

- Investigate the source and hash of any detected Sliver binaries.
- Review command-line arguments for C2 configuration details (e.g., C2 server, protocol, port).
- Correlate with network logs for outbound connections to suspicious IPs or domains.
- Validate if the activity is part of authorized red team operations.

---

## False Positives

False positives may occur if:

- Red team or penetration testing activities are authorized and using Sliver.
- Security research or malware analysis labs are running Sliver for testing.

---

## Recommended Response Actions

1. Investigate the detected process and its parent/child relationships.
2. Analyze command-line arguments for C2 infrastructure or operator activity.
3. Review network connections initiated by the process for suspicious destinations.
4. Isolate affected endpoints if compromise is confirmed.
5. Hunt for additional persistence or lateral movement from the same host.

---

## References

- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK: T1090.001 – Proxy: Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)
- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1573.002 – Encrypted Channel: Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002/)
- [Sliver C2 Framework – Official Documentation](https://github.com/BishopFox/sliver)
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-02 | Initial Detection | Created hunt query to detect Sliver C2 activity via web protocols and suspicious binaries   |
