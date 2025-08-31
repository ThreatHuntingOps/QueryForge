# Detection of Common RMM Tools for Persistence

## Severity or Impact of the Detected Behavior
- **Risk Score:** 60
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-RMM-Abuse
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** High

---

## Hunt Analytics

This hunt detects the execution of common Remote Monitoring and Management (RMM) tools. While these tools are legitimate and widely used by IT departments, they are also frequently abused by threat actors, such as the Chaos ransomware group, for persistence, command and control, and remote access. Identifying the execution of these tools in environments where they are not standard-issue or authorized can be a strong indicator of compromise. This hunt is most effective when cross-referenced with an inventory of approved software.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0011 - Command and Control  | T1219       | —            | Remote Access Software                         |
| TA0003 - Persistence          | T1133       | —            | External Remote Services                       |

---

## Hunt Query Logic

This query identifies potential RMM abuse by looking for:

- Process creation events (`PROCESS_START`).
- Process names that match a list of known RMM tool executables, including AnyDesk, ScreenConnect (ConnectWise Control), Splashtop, and others.

The effectiveness of this query relies on an organization's ability to distinguish between legitimate and unauthorized use.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: RMM Software Execution for Persistence
// Description: Detects the execution of common RMM tools (AnyDesk, ScreenConnect, Splashtop, etc.) used by threat actors like Chaos RaaS for persistent remote access.
// MITRE ATT&CK TTP ID: T1219

#event_simpleName=ProcessRollup2
| event_platform = Win
| (
    FileName = /anydesk\.exe/i OR
    FileName = /screenconnect\.exe/i OR
    FileName = /client\.screenconnect\.com/i OR
    FileName = /optitune\.exe/i OR
    FileName = /syncrormm\.exe/i OR
    FileName = /splashtop\.exe/i OR
    FileName = /splashtopstreamer\.exe/i OR
    OriginalFileName = /anydesk\.exe/i OR
    OriginalFileName = /screenconnect\.exe/i OR
    OriginalFileName = /client\.screenconnect\.com/i OR
    OriginalFileName = /optitune\.exe/i OR
    OriginalFileName = /syncrormm\.exe/i OR
    OriginalFileName = /splashtop\.exe/i OR
    OriginalFileName = /splashtopstreamer\.exe/i
  )
| table([EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId, PlatformName])
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The user or attacker must have sufficient permissions to install and execute applications on the endpoint.
- **Required Artifacts:** Process creation logs.

---

## Considerations

- **High False Positive Potential:** This query will generate a high volume of alerts in environments where RMM tools are used for legitimate IT support.
- **Asset Inventory is Key:** The value of this hunt is realized by comparing its findings against a list of approved software and standard operating procedures.
- **Contextual Analysis:** Investigate the parent process of the RMM tool. Was it launched by a user clicking an email link, or was it spawned by another suspicious process?

---

## False Positives

False positives are expected and will occur whenever:
- IT administrators or help desk personnel use these tools for legitimate remote support.
- End-users have permission to use these tools for remote work or collaboration.

---

## Recommended Response Actions

1.  **Verify Legitimacy:** The first step is to confirm if the detected RMM tool is authorized for use on the specific endpoint and by the specific user. Consult your organization's software policy.
2.  **Investigate Causality:** If the usage is unauthorized, analyze the parent process and causality chain to determine how the software was installed and executed. Look for droppers, malicious scripts, or suspicious email attachments.
3.  **Analyze Network Connections:** Examine the network connections made by the RMM tool. Are they connecting to known, legitimate company or vendor IP addresses, or to suspicious, unknown infrastructure?
4.  **Isolate and Remediate:** If malicious activity is confirmed, isolate the endpoint and begin remediation procedures.

---

## References

- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK: T1133 – External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect the execution of common RMM tools.      |
