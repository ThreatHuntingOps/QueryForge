# Detection of Volume Shadow Copy Deletion via VSSAdmin or WMIC (FakePenny Ransomware)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-ShadowCopyDeletion
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects attempts by ransomware to delete volume shadow copies, a common technique used to inhibit system recovery and maximize the impact of ransomware attacks. The detection logic focuses on the use of `vssadmin.exe` or `wmic.exe` with command-line arguments that delete shadow copies or shadow storage. This behavior is strongly associated with destructive ransomware campaigns, including FakePenny.

Such activity is indicative of indicator removal, system recovery inhibition, and destructive impact on victim environments.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0040 - Impact              | T1490       | —            | Inhibit System Recovery                                |
| TA0005 - Defense Evasion     | T1070.006   | —            | Indicator Removal on Host: File Deletion               |
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell          |

---

## Hunt Query Logic

This query identifies suspicious shadow copy deletion attempts by detecting:

- Process file name matching `vssadmin.exe` or `wmic.exe`
- Command line containing `delete shadows`, `shadowcopy delete`, or `shadowstorage delete`

These patterns are commonly seen in ransomware attacks aiming to prevent recovery and maximize damage.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (FileName = /vssadmin\.exe/i OR FileName = /wmic\.exe/i)  
| CommandLine = "*delete shadows*" OR CommandLine = "*shadowcopy delete*" OR CommandLine = "*shadowstorage delete*"  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute administrative commands to delete shadow copies.
- **Required Artifacts:** Process creation logs, command-line arguments.

---

## Considerations

- Validate the context and user responsible for the shadow copy deletion attempt.
- Investigate the process lineage for signs of ransomware or destructive activity.
- Correlate with other endpoint or network alerts for data encryption or system recovery inhibition.

---

## False Positives

False positives may occur if:

- System administrators or backup processes legitimately delete shadow copies as part of maintenance.
- Security testing or red team activities mimic these behaviors.

---

## Recommended Response Actions

1. Isolate the affected endpoint if ransomware or destructive activity is confirmed.
2. Investigate the process and user context responsible for the deletion command.
3. Review system and backup status to assess recovery options.
4. Initiate incident response and recovery procedures as appropriate.
5. Update detection rules and threat intelligence with new indicators as needed.

---

## References

- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1070.006 – Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/006/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks (Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-09 | Initial Detection | Created hunt query to detect volume shadow copy deletion via VSSAdmin or WMIC               |
