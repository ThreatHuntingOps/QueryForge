# Detection of Suspicious Rundll32 Execution of Cobalt Strike Beacons with Malicious Network Connections

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Rundll32-CobaltStrike-MaliciousNetConn
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects instances where `rundll32.exe` is used to execute Cobalt Strike beacon DLLs (`vm.dll`, `vm80.dll`) while connecting to suspicious domains (such as `*.misstallion.com`) or known malicious IPs. This behavior is often associated with credential access, post-exploitation, and C2 activity. Detected behaviors include:

- Process launches of `rundll32.exe` with command lines referencing `vm.dll` or `vm80.dll`
- Command lines containing suspicious domains (e.g., `misstallion.com`) or other indicators of network-based C2
- Full process and user context for investigation

These techniques are associated with process injection, defense evasion, credential access, and post-exploitation activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1055.001   | —            | Process Injection: Dynamic-link Library Injection |
| TA0005 - Defense Evasion     | T1218.011   | —            | Signed Binary Proxy Execution: Rundll32        |
| TA0006 - Credential Access   | T1003       | —            | OS Credential Dumping                         |

---

## Hunt Query Logic

This query identifies suspicious DLL execution and network activity by looking for:

- Process starts of `rundll32.exe` with command lines referencing `vm.dll` or `vm80.dll`
- Command lines containing suspicious domains (e.g., `misstallion.com`, `.com`) or DLL references
- Full process and user context for triage

These patterns are indicative of Cobalt Strike beacon execution with malicious network connections.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Suspicious Rundll32 Execution of Cobalt Strike Beacons with Malicious Network Connections
// Description: Detects rundll32.exe executing vm.dll or vm80.dll and connecting to suspicious domains (e.g., *.misstallion.com), a behavior associated with Cobalt Strike and credential access.
// MITRE ATT&CK TTP ID: T1055.001
// MITRE ATT&CK TTP ID: T1218.011
// MITRE ATT&CK TTP ID: T1003

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "rundll32.exe"
| (CommandLine = "*vm.dll*" or CommandLine = "*vm80.dll*")
| (CommandLine = "*misstallion.com*" or CommandLine = "*.com*" or CommandLine = "*.dll*")
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, CausalityActorProcessCommandLine, CausalityActorPrimaryUsername, SHA256FileHash, EventID, AgentId])
| sort(EventTimestamp)
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |
---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to execute rundll32.exe and load DLLs.
- **Required Artifacts:** Process creation logs, command-line arguments, and process ancestry information.

---

## Considerations

- Review the source and context of the rundll32.exe process and command line for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent lateral movement, credential access, or C2 activity.

---

## False Positives

False positives may occur if:

- IT administrators or legitimate tools use rundll32.exe to execute benign DLLs with similar command lines.
- Automated deployment tools or scripts generate and execute these commands for legitimate purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review user activity and system logs for signs of compromise, credential access, or lateral movement.
3. Analyze any subsequent network connections or file transfers.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious rundll32.exe usage and known malicious domains or IPs.

---

## References

- [MITRE ATT&CK: T1055.001 – Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)
- [MITRE ATT&CK: T1218.011 – Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK: T1003 – OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect suspicious rundll32 execution of Cobalt Strike beacons with malicious network connections |
