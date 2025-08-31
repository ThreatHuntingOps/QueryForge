
# Detection of Microsoft Quick Assist for Potential Remote Access Abuse

## Severity or Impact of the Detected Behavior
- **Risk Score:** 70
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-InitialAccess-MSRA-Abuse
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** High

---

## Hunt Analytics

This hunt detects the execution of `msra.exe` (Microsoft Quick Assist). While `msra.exe` is a legitimate Windows remote assistance tool, threat actors, such as the Chaos group, exploit it for initial access through social engineering (vishing). An attacker convinces a user to run the tool and provide a connection code, granting the actor remote control of the system. Monitoring for `msra.exe` executions, especially if they are not associated with legitimate IT support activity, can provide early-stage detection of this type of attack.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0001 - Initial Access       | T1598       | .004         | Phishing for Information: Voice Phishing       |
| TA0011 - Command and Control  | T1219       | —            | Remote Access Software                         |

---

## Hunt Query Logic

This query identifies the execution of Microsoft Quick Assist by looking for:

- Process creation events (`PROCESS_START`) on Windows endpoints.
- The process image name is `msra.exe`.

An alert from this query is a starting point for an investigation to determine if the usage was legitimate or part of a social engineering attack.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Microsoft Quick Assist Execution for Potential Vishing-Based Initial Access
// Description: Detects the execution of Microsoft Quick Assist (msra.exe), which can be abused by threat actors for initial access, as seen in Chaos ransomware attacks.
// MITRE ATT&CK TTP ID: T1219
// MITRE ATT&CK TTP ID: T1598.004

#event_simpleName=ProcessRollup2
| event_platform = Win
| (FileName = /msra\.exe/i OR OriginalFileName = /msra\.exe/i)
| table([EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId, PlatformName])
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** A local user must be convinced to execute `msra.exe` and share the connection code with the attacker.
- **Required Artifacts:** Process creation logs with command-line arguments from an EDR or equivalent host monitoring tool.

---

## Considerations

- Context is critical. This activity must be correlated with other data points to determine if it is malicious.
- Check for help desk tickets or other internal communications that would justify the use of Quick Assist.
- Review subsequent process and network activity on the host for signs of discovery, credential access, or payload downloads.

---

## False Positives

False positives are expected and will occur if:

- Internal IT support or help desk staff legitimately use Microsoft Quick Assist to provide remote assistance to users.
- Users employ the tool for personal reasons, such as helping friends or family with computer issues.

---

## Recommended Response Actions

1.  **Verify Legitimacy:** Contact the user and their manager to determine if they initiated or expected a remote assistance session. Check against internal IT support records.
2.  **Analyze Subsequent Activity:** If the session was not legitimate, immediately investigate all subsequent process, network, and file activity on the host for indicators of compromise.
3.  **Isolate Endpoint:** If malicious activity is confirmed, isolate the affected endpoint from the network to prevent lateral movement.
4.  **User Education:** If the event was a failed or successful social engineering attempt, use it as an opportunity to reinforce security awareness training regarding unsolicited requests for remote access.

---

## References

- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK: T1598.004 – Phishing for Information: Voice Phishing](https://attack.mitre.org/techniques/T1598/004/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect the abuse of Microsoft Quick Assist for initial access, as seen with the Chaos ransomware group. |
