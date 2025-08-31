# Detection of Shadow Copy Deletion Using vssadmin.exe

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-vssadmin-ShadowCopyDeletion
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of `vssadmin.exe` to delete all shadow copies on a system. This is a well-known technique used by ransomware operators and other threat actors to inhibit system recovery and prevent restoration of encrypted or deleted files. The query focuses on command-line arguments that invoke the deletion of shadow copies, which is a strong indicator of malicious activity, especially when observed outside of normal backup or maintenance windows.

Detected behaviors include:

- Use of `vssadmin.exe` with the `Delete Shadows` command
- Attempts to remove all volume shadow copies to prevent file recovery
- Commonly observed in ransomware and destructive attack campaigns

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion      | T1070.004   | —            | Indicator Removal on Host: File Deletion      |
| TA0040 - Impact               | T1490       | —            | Inhibit System Recovery                       |

---

## Hunt Query Logic

This query identifies suspicious executions of `vssadmin.exe` with command-line arguments that delete shadow copies. Such patterns are often seen in ransomware attacks and other destructive operations.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    

| (FileName = "vssadmin.exe")    

| CommandLine = "*Delete Shadows*" 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to run `vssadmin.exe` and delete shadow copies.
- **Required Artifacts:** Process creation logs, command-line arguments, shadow copy status.

---

## Considerations

- Investigate the user account and host context for the detected `vssadmin.exe` activity.
- Review for additional signs of ransomware or destructive activity.
- Correlate with other suspicious events, such as backup deletion or file encryption.
- Check for legitimate backup or maintenance operations that may explain the activity.

---

## False Positives

False positives may occur if:

- Administrators are performing legitimate maintenance or backup management.
- Automated scripts or IT tools are used for scheduled shadow copy cleanup.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the shadow copy deletion.
2. Review recent activity for signs of ransomware or destructive attacks.
3. Check for additional indicators of compromise or evidence removal.
4. Isolate affected systems if malicious activity is confirmed.
5. Restore shadow copies and files from backups if possible.

---

## References

- [MITRE ATT&CK: T1070.004 – Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-09 | Initial Detection | Created hunt query to detect shadow copy deletion using vssadmin.exe                       |
