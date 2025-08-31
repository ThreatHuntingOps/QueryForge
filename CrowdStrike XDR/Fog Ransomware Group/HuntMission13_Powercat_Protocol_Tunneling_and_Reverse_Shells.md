# Detection of Powercat-Based Protocol Tunneling and Reverse Shell Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Powercat-Tunneling
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects malicious use of Powercat, a PowerShell-based post-exploitation tool that emulates Netcat functionalities. Powercat is frequently leveraged by adversaries for establishing reverse or bind shells, tunneling, and exfiltrating data over alternative protocols such as TCP, UDP, and DNS. The detection focuses on identifying Powercat script execution (e.g., `powercat.ps1`), suspicious command-line arguments (such as `-c`, `-l`, `-r`, `-e`, `-t`, `-udp`, `-dns`, `--reverse`), and encoded payloads (e.g., `iex` with `frombase64string` and `powercat`). These behaviors are strong indicators of lateral movement, command-and-control, or data exfiltration attempts in compromised environments.

Key detection behaviors include:

- Execution of Powercat scripts (`powercat.ps1`)
- Command-line arguments associated with reverse/bind shells and tunneling
- Use of encoded payloads to obfuscate Powercat execution
- PowerShell process invocation (`powershell.exe`, `pwsh.exe`)

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0011 - Command and Control  | T1572       | —            | Protocol Tunneling                                     |
| TA0002 - Execution            | T1059.001   | —            | Command and Scripting Interpreter: PowerShell          |
| TA0011 - Command and Control  | T1090.001   | —            | Proxy: Internal Proxy                                  |
| TA0010 - Exfiltration         | T1048.003   | —            | Exfiltration Over Alternative Protocol: Over DNS       |
| TA0004 - Privilege Escalation | T1055       | —            | Process Injection (in combination with payloads)       |

---

## Hunt Query Logic

This query identifies suspicious executions of Powercat scripts and related command-line arguments:

- Process creation events for `powercat.ps1` or command lines referencing Powercat
- Command-line arguments indicating reverse/bind shell, tunneling, or protocol usage (`-c`, `-l`, `-r`, `-e`, `-t`, `-udp`, `-dns`, `--reverse`)
- Encoded payloads using `iex` and `frombase64string` with Powercat
- PowerShell process invocation

These patterns are strong indicators of Powercat-based protocol tunneling or reverse shell activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (FileName = /powercat\.ps1/i OR CommandLine = "*powercat.ps1*")  
| (CommandLine = "*-c*" OR CommandLine = "*-l*"  
OR CommandLine = "*-r*" OR CommandLine = "*-e*" OR CommandLine = "*-t*"  
OR CommandLine = "*-udp*" OR CommandLine = "*-dns*" OR CommandLine = "*--reverse*" 
OR CommandLine = "*iex*" AND CommandLine = "*frombase64string*" AND CommandLine = "*powercat*") 
| (ImageFileName = "*powershell.exe*" OR ImageFileName = "*pwsh.exe*") 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PowerShell scripts on the endpoint.
- **Required Artifacts:** Powercat script files, process creation logs, command-line arguments.

---

## Considerations

- Investigate the source and hash of any detected Powercat scripts.
- Review command-line arguments for protocol tunneling or reverse shell configuration.
- Correlate with network logs for outbound connections over non-standard protocols (TCP, UDP, DNS).
- Validate if the activity is part of authorized red team or penetration testing operations.

---

## False Positives

False positives may occur if:

- Red team or penetration testing activities are authorized and using Powercat.
- Security research or malware analysis labs are running Powercat for testing.

---

## Recommended Response Actions

1. Investigate the detected process and its parent/child relationships.
2. Analyze command-line arguments for tunneling or reverse shell indicators.
3. Review network connections initiated by the process for suspicious destinations or protocols.
4. Isolate affected endpoints if compromise is confirmed.
5. Hunt for additional persistence or lateral movement from the same host.

---

## References

- [MITRE ATT&CK: T1572 – Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1090.001 – Proxy: Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)
- [MITRE ATT&CK: T1048.003 – Exfiltration Over DNS](https://attack.mitre.org/techniques/T1048/003/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Powercat – PowerShell Netcat](https://github.com/besimorhino/powercat)
- [CrowdStrike: Detecting Powercat Activity](https://www.crowdstrike.com/blog/detecting-powercat-activity/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-02 | Initial Detection | Created hunt query to detect Powercat-based protocol tunneling and reverse shell activity   |
