# Detection of Fileless Execution via memfd_create and fexecve Syscalls (VShell Implant)

## Hunt Analytics Metadata

- **ID:** `HuntQuery-Linux-Fileless-VShell-Behavioral`
- **Operating Systems:** `LinuxEndpoint`, `LinuxServer`
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects behavioral indicators of fileless malware execution on Linux, focusing on the VShell backdoor as observed in UNC5174’s SNOWLIGHT campaign. VShell leverages the `memfd_create` syscall (0x13f) to create anonymous in-memory file descriptors, which are then executed using `fexecve`. The implant often masquerades as a legitimate system process (e.g., `kworker/0:2`) and communicates with C2 domains such as `vs.gooogleasia.com`.

Detection logic is based on behavioral patterns, not static IOCs, to identify stealthy, fileless malware activity. Key behaviors include:

- Creation or execution of in-memory file descriptors (e.g., `memfd_create`, `fexecve`)
- Suspicious process names or masquerading as system processes (e.g., `kworker`)
- DNS or network connections to known or lookalike C2 domains
- Use of specific command-line arguments or hash values associated with VShell

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0005 - Defense Evasion     | T1055.012   | —            | Process Injection: memfd_create                        |
| TA0002 - Execution           | T1106       | —            | Native API Execution                                   |
| TA0005 - Defense Evasion     | T1027.002   | —            | Obfuscated Files or Information: Software Packing      |
| TA0005 - Defense Evasion     | T1036.004   | —            | Masquerading: Masquerade Task or Service               |
| TA0002 - Execution           | T1218       | —            | Signed Binary Proxy Execution                          |
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                         |

---

## Hunt Query Logic

This query identifies suspicious fileless execution and masquerading behaviors:

- Process or file names matching `memfd.*`, `a`, or `kworker*`
- Command lines referencing `memfd_create` or `fexecve`
- DNS or network connections to `vs.gooogleasia.com`
- Command lines with C2-like HTTP query patterns
- Known VShell hash values

These patterns are indicative of fileless malware leveraging in-memory execution and masquerading techniques.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/SysmonEvent|ProcessRollup2|DnsRequest|NetworkConnectIP4/  
| (FileName=/^memfd\..*/i OR FileName=/^a$/ OR FileName=/^kworker.*/ OR FileName=/kworker\/0:2/)  
OR (CommandLine=/.*memfd_create.*/i OR CommandLine=/.*fexecve.*/i)  
OR (DnsRequest = "vs.gooogleasia.com" OR RemoteAddress = "vs.gooogleasia.com")  
OR (CommandLine=/.*\/\?a=l64&h=vs\.gooogleasia\.com.*/i) 
OR (SHA256HashData = "8d88944149ea1477bd7ba0a07be3a4371ba958d4a47b783f7c10cbe08c5e7d38")   
```

---

## Data Sources

| Log Provider | Event ID | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|--------------------|---------------------|------------------------|
| Falcon       | N/A      | SysmonEvent        | Process, Network    | Syscall, Network, DNS  |
| Falcon       | N/A      | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A      | DnsRequest         | Network             | DNS Query              |
| Falcon       | N/A      | NetworkConnectIP4  | Network             | Network Connection     |

---

## Execution Requirements

- **Required Permissions:** Attacker or user must be able to invoke syscalls and execute in-memory payloads.
- **Required Artifacts:** Syscall logs, process creation logs, network and DNS logs, binary hashes.

---

## Considerations

- Review the context of in-memory execution and process masquerading.
- Investigate the parent process and user context for privilege escalation or lateral movement.
- Correlate with threat intelligence for domain and hash enrichment.
- Examine for additional persistence or lateral movement mechanisms.

---

## False Positives

False positives may occur if:

- Legitimate applications use `memfd_create` or `fexecve` for in-memory execution.
- System processes or security tools use similar process names or techniques.
- Internal testing or red team activity mimics fileless malware behavior.

---

## Recommended Response Actions

1. Investigate the process and user responsible for the suspicious activity.
2. Review the destination domains and IPs for known malicious infrastructure.
3. Analyze the binary and memory regions for VShell or other fileless malware artifacts.
4. Check for additional persistence or lateral movement mechanisms.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1055.012 – Process Injection: memfd_create](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK: T1106 – Native API Execution](https://attack.mitre.org/techniques/T1106/)
- [MITRE ATT&CK: T1027.002 – Obfuscated Files or Information: Software Packing](https://attack.mitre.org/techniques/T1027/002/)
- [MITRE ATT&CK: T1036.004 – Masquerading: Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004/)
- [MITRE ATT&CK: T1218 – Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [UNC5174’s evolution in China’s ongoing cyber warfare: From SNOWLIGHT to VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-23 | Initial Detection | Created hunt query to detect fileless execution via memfd_create and fexecve (VShell)      |
