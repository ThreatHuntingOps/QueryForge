# Detection of Persistence Mechanisms Leveraging SplitLoader

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-SplitLoaderPersistence
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects persistence mechanisms involving SplitLoader or associated payloads. It focuses on two common techniques: modification of registry Run keys and the creation or modification of Scheduled Tasks. Both are frequently used by threat actors, including Moonstone Sleet, to maintain access after initial compromise. The detection logic looks for references to SplitLoader, DLLs, or executables in registry or scheduled task data fields.

Such persistence methods are critical for long-term access and are often used in targeted attacks to ensure malware survives reboots and user logins.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0003 - Persistence         | T1547.001   | —            | Boot or Logon Autostart Execution: Registry Run Keys   |
| TA0003 - Persistence         | T1053.005   | —            | Scheduled Task/Job: Scheduled Task                     |

---

## Hunt Query Logic

This query identifies suspicious persistence mechanisms by detecting:

- Registry modifications to `Run` keys or scheduled task registration events
- Data fields referencing `SplitLoader`, `.dll`, or `.exe` payloads

These patterns are commonly seen in attacks where malware establishes persistence via registry or scheduled tasks.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ScheduledTaskRegistered OR #event_simpleName=RegistryModification  
| (TargetObject = "*\\Microsoft\\Windows\\CurrentVersion\\Run\\*" OR TargetObject = "*\\Tasks\\*")  
| (Data = "*SplitLoader*" OR Data = "*.dll" OR Data = "*.exe")
```

---

## Data Sources

| Log Provider | Event ID | Event Name              | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|-------------------------|---------------------|------------------------|
| Falcon       | N/A      | ScheduledTaskRegistered | Scheduled Task      | Scheduled Task Creation|
| Falcon       | N/A      | RegistryModification    | Registry            | Registry Key/Value Modification |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have rights to modify registry Run keys or create scheduled tasks.
- **Required Artifacts:** Registry modification logs, scheduled task registration logs, payload file information.

---

## Considerations

- Validate the legitimacy of any new or modified Run keys or scheduled tasks.
- Investigate the referenced payloads for signs of tampering or malicious intent.
- Correlate with other endpoint or network alerts for signs of persistence or lateral movement.

---

## False Positives

False positives may occur if:

- Legitimate software installs itself for persistence using Run keys or scheduled tasks.
- System administrators or automation tools create scheduled tasks or modify Run keys for valid reasons.
- Security testing or red team activities mimic these behaviors.

---

## Recommended Response Actions

1. Review and validate the legitimacy of the detected persistence mechanism.
2. Analyze the referenced payload (DLL or EXE) for malicious content.
3. Investigate user and process activity around the time of modification or registration.
4. Remove unauthorized persistence mechanisms if confirmed malicious.
5. Update detection rules and threat intelligence with new indicators as needed.

---

## References

- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1053.005 – Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks (Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-09 | Initial Detection | Created hunt query to detect SplitLoader persistence via registry and scheduled tasks        |
