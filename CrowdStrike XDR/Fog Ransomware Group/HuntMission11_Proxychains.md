
# Detection of Proxychains Usage to Route Post-Exploitation Traffic via C2 Infrastructure

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-ProxychainsDetection
- **Operating Systems:** LinuxEndpoint, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt identifies usage of `proxychains` in combination with known post-exploitation tools. Adversaries use Proxychains to route offensive traffic through multiple proxies, masking its origin and intent. Proxychains can obscure tool usage and redirect execution through C2-controlled infrastructure. This query helps detect:

- Execution of tools like Certipy, noPac, Impacket, Sliver, or Cobalt Strike via Proxychains
- Invocation of Proxychains binary itself (including variants like proxychains4 or proxychains-ng)
- Obfuscation or tunneling activity meant to evade host-based telemetry

This behavior often precedes credential theft, lateral movement, or external exfiltration attempts.

---

## ATT&CK Mapping

| Tactic                     | Technique   | Subtechnique | Technique Name                           |
|---------------------------|-------------|---------------|------------------------------------------|
| TA0011 - Command and Control | T1090     | 003           | Proxy: Multi-hop Proxy                   |
| TA0005 - Defense Evasion    | T1027     | —             | Obfuscated Files or Information          |
| TA0011 - Command and Control | T1572     | —             | Protocol Tunneling                       |
| TA0011 - Command and Control | T1105     | —             | Ingress Tool Transfer                    |
| TA0002 - Execution          | T1219     | —             | Remote Access Software                   |

---

## Hunt Query Logic

This query looks for command-line or binary usage of Proxychains with known tools:

- Direct Proxychains invocation
- Proxychains used with popular post-exploitation tools (e.g., Impacket, Sliver, Certipy)
- Proxychains variants (proxychains-ng, proxychains4)

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (CommandLine = "*proxychains*"   
OR CommandLine = "*proxychains* certipy*"   
OR CommandLine = "*proxychains* nopac*"   
OR CommandLine = "*proxychains* python*"   
OR CommandLine = "*proxychains* impacket*"   
OR CommandLine = "*proxychains* sliver*"   
OR CommandLine = "*proxychains* cobaltstrike*")   
| (ImageFileName = "*proxychains*" OR CommandLine = "*proxychains4*" OR CommandLine = "*proxychains-ng*")
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have access to execute binaries/tools with Proxychains.
- **Required Artifacts:** Process execution logs, command-line arguments, binary names.

---

## Considerations

- Investigate source and destination IPs used during execution.
- Check for other tools or scripts launched in conjunction with Proxychains.
- Look for related network tunneling or evasion behavior.

---

## False Positives

False positives may occur if:

- Developers or red teamers legitimately use Proxychains for tunneling during testing.
- Network admins test proxy paths using automation or custom tooling.

---

## Recommended Response Actions

1. Confirm the context of the Proxychains usage—red team vs unauthorized.
2. Inspect destination servers or domains accessed via proxied execution.
3. Review full execution chains for credential theft or file staging.
4. Quarantine systems involved in confirmed malicious behavior.
5. Apply detections for associated tools (e.g., Impacket, Sliver, Certipy).

---

## References

- [MITRE ATT&CK: T1090.003 – Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
- [MITRE ATT&CK: T1572 – Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-02 | Initial Detection | Detection of Proxychains used to route execution of offensive tooling across infrastructure |
