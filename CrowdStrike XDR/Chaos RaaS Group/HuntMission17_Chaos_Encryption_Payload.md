# Detection of Chaos Ransomware Encryption Command-Line Arguments

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Chaos-EncryptionPayload
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** None

---

## Hunt Analytics

This is a high-fidelity hunt query that detects the execution of the Chaos ransomware payload. It specifically looks for the unique combination of command-line arguments (`/lkey`, `/encrypt_step`, `/work_mode`, `/ignorar_arquivos_grandes`) that the actor uses to initiate the encryption process. Since the executable name can vary, focusing on these specific arguments is a more resilient detection strategy. An alert from this query indicates that the ransomware is actively being executed in the environment and represents a major security incident in progress.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact                      |

---

## Hunt Query Logic

This query identifies the active Chaos ransomware encryption process by looking for the simultaneous presence of four specific command-line arguments that are unique to its execution:
- `/lkey:`
- `/encrypt_step:`
- `/work_mode:`
- `/ignorar_arquivos_grandes`

The presence of all four in a single command line is a definitive signature of this payload.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Chaos Ransomware Encryption Process Execution (Comprehensive)
// Description: Detects the execution of the Chaos ransomware payload by identifying its unique and comprehensive set of command-line arguments used for encryption.
// MITRE ATT&CK TTP ID: T1486

#event_simpleName=ProcessRollup2
| event_platform = Win
| CommandLine = "*/lkey:*"
| CommandLine = "*/encrypt_step:*"
| CommandLine = "*/work_mode:*"
| CommandLine = "*/ignorar_arquivos_grandes*"
| table([EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId, PlatformName])
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User-level permissions are typically sufficient for the ransomware to encrypt files within that user's context.
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- **Active Encryption:** This alert means files are actively being encrypted. This is not a precursor; it is the impact event itself.
- **Critical IOCs:** The executable name (`action_process_image_name`), path (`action_process_image_path`), and hash (`causality_actor_process_image_sha256`) are the most critical IOCs to collect from this alert.
- **Parent Process:** The parent process (`actor_process_image_name`) reveals how the payload was launched (e.g., from a scheduled task, a remote WMIC command, etc.).

---

## False Positives

- There are no known false positives for this query. This specific combination of arguments is unique to the Chaos ransomware payload. Any alert should be treated as a confirmed true positive.

---

## Recommended Response Actions

1.  **Isolate Host Immediately:** This is the absolute first step. Unplug the network cable if necessary. The goal is to stop the encryption and prevent lateral spread.
2.  **Collect and Analyze Payload:** Immediately retrieve the ransomware executable identified in the alert for forensic analysis.
3.  **Hunt for Hash:** Take the file hash of the ransomware payload and hunt for it across the entire environment to identify any other systems where it may have been dropped.
4.  **Investigate Causality:** Trace the parent process to understand the full attack chain and identify how the payload was delivered and executed.
5.  **Activate Incident Response Plan:** This is a major incident. Activate your full ransomware incident response plan.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created high-fidelity hunt for the Chaos ransomware encryption payload. |
