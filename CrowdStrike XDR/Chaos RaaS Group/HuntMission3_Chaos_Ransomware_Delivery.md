# Detection of PowerShell Modifying Windows Delivery Optimization

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PS-DeliveryOptimization-Chaos
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a highly specific PowerShell command used by the Chaos ransomware group. The command modifies the Windows Delivery Optimization service settings to allow the download of large files from a local peer server (localhost:8005). This is a key preparatory step used by the actor to stage larger malicious payloads or tools on compromised systems efficiently and stealthily. The specificity of this command makes this a high-fidelity indicator of this particular threat actor's activity.

Detected behaviors include:
- A `powershell.exe` process launch.
- A command line containing `Get-DeliveryOptimizationStatus`, `localhost`, `8005`, and `FileSize -ge`.

These techniques are associated with payload staging and subsequent ransomware execution.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0002 - Execution            | T1059       | .001         | Command and Scripting Interpreter: PowerShell  |
| TA0011 - Command and Control  | T1105       | —            | Ingress Tool Transfer                          |

---

## Hunt Query Logic

This query identifies a specific PowerShell command by looking for:

- A process name matching `powershell.exe`.
- Command line arguments containing the specific combination of `Get-DeliveryOptimizationStatus`, `localhost`, `8005`, and `FileSize -ge`.

This exact combination of parameters is a strong indicator of the Chaos ransomware group's preparatory activities for payload delivery.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Chaos RaaS PowerShell Delivery Optimization Modification
// Description: Detects a specific PowerShell command used by Chaos RaaS to alter Windows Delivery Optimization settings for downloading large payloads from a local peer.
// MITRE ATT&CK TTP ID: T1059.001

#event_simpleName=ProcessRollup2
| event_platform = Win
| (FileName = /powershell\.exe/i OR OriginalFileName = /powershell\.exe/i)
| CommandLine = "*Get-DeliveryOptimizationStatus*"
| CommandLine = "*localhost*"
| CommandLine = "*8005*"
| CommandLine = "*FileSize -ge*"
| table([EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId, PlatformName])
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have sufficient permissions to execute PowerShell commands.
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- Due to the high fidelity of this indicator, any alert should be treated as a high-priority incident.
- Investigate the causality chain: what process spawned this PowerShell command? This can help identify the initial infection vector.
- Examine the filesystem for recently created or modified large files, which could be the payload staged via this technique.
- Correlate with network logs to see if the device attempts to download anything after this command is run, even if the command itself points to localhost.

---

## False Positives

- False positives are highly unlikely given the specificity of the command-line arguments.
- There are no known legitimate administrative tools that use this exact command structure. Any match should be considered suspicious and investigated thoroughly.

---

## Recommended Response Actions

1.  **Isolate:** Immediately isolate the affected endpoint from the network to prevent lateral movement or further payload execution.
2.  **Investigate:** Analyze the parent process and causality chain to understand the initial access vector.
3.  **Hunt:** Search for the staged payload on the device. Look for other indicators of Chaos ransomware activity across the environment.
4.  **Remediate:** Terminate the malicious processes, delete any staged payloads, and address the root cause of the compromise.
5.  **Monitor:** Implement blocking rules for any identified C2 infrastructure and enhance monitoring for similar PowerShell abuse.

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect Chaos ransomware payload staging technique. |
