# Detection of Chaos Ransom Note File Creation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Chaos-RansomNote
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** None

---

## Hunt Analytics

This hunt query detects the creation of the specific ransom note file, `readme.chaos.txt`. This is a definitive indicator that the Chaos ransomware has completed its encryption routine and is now delivering its ransom demand. The creation of a file with this exact name is a very high-confidence signal of this specific ransomware's presence and is one of the last observable actions in its attack chain. An alert from this query confirms a successful ransomware attack on the host.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact                      |

---

## Hunt Query Logic

This query identifies the Chaos ransom note by monitoring for file creation, write, or rename events where the target filename is exactly `readme.chaos.txt`. This is a unique artifact of the Chaos ransomware.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Chaos Ransom Note Creation
// Description: Detects the creation of the specific ransom note file "readme.chaos.txt", a definitive indicator of the Chaos ransomware impact stage.
// MITRE ATT&CK TTP ID: T1486

#event_simpleName=FileCreateInfo
| event_platform = Win
| (FileName = /readme\.chaos\.txt/i OR OriginalFileName = /readme\.chaos\.txt/i)
| table([EventTimestamp, ComputerName, UserName, FileName, FilePath, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId, PlatformName])
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User-level permissions are sufficient for the ransomware to drop its note.
- **Required Artifacts:** File creation/modification event logging.

---

## Considerations

- **Post-Impact Indicator:** This alert signifies that data encryption has already occurred. It is a confirmation of impact, not a precursor.
- **Definitive IOC:** The process that created the file (`actor_process_image_name`) is the ransomware executable. Its hash and path are critical IOCs for incident response and hunting.
- **Attribution:** This alert provides strong evidence for attributing the activity to the Chaos ransomware family.

---

## False Positives

- There are no known false positives for this query. The filename is specific to this ransomware. Any alert should be treated as a confirmed true positive.

---

## Recommended Response Actions

1.  **Isolate Host Immediately:** Although the primary damage is done, isolating the host prevents any potential secondary actions or cleanup by the malware.
2.  **Activate Incident Response Plan:** This alert confirms a ransomware incident. Activate your full ransomware IR plan.
3.  **Identify and Collect Payload:** The `actor_process_image_path` field points directly to the ransomware executable. Collect this binary for analysis.
4.  **Hunt for Payload Hash:** Use the hash of the ransomware executable to hunt across the environment for other systems where the payload may exist.
5.  **Do Not Delete:** Do not delete the ransom note immediately. It may contain information needed for recovery if you choose to engage with the threat actor (not generally recommended). Preserve it as evidence.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created high-fidelity hunt for the Chaos ransomware note creation.   |
