# Detection of Rclone File Deletion and Evidence Removal via Windows Utilities

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Rclone-ArtifactDeletion
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of Windows command-line utilities (`cmd.exe`) to delete Rclone-related files and scripts, which is a common tactic used by threat actors to remove evidence of data exfiltration and evade detection. The query focuses on command-line arguments that indicate deletion of Rclone executables, batch files, and related artifacts. Such actions are often accompanied by additional evidence removal steps, such as clearing event logs, deleting shadow copies, or modifying symbolic link behavior, to inhibit recovery and forensic analysis.

Detected behaviors include:

- Use of `cmd.exe` to delete files named `rclone`, `rcl.bat`, or `nocmd.vbs`
- Attempts to remove evidence of Rclone usage after data exfiltration
- Potential follow-on actions to clear logs or delete backups

These actions are frequently observed in ransomware and data theft operations, especially during the cleanup phase.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion      | T1070.004   | —            | Indicator Removal on Host: File Deletion      |
| TA0005 - Defense Evasion      | T1070.001   | —            | Indicator Removal on Host: Clear Windows Event Logs |
| TA0040 - Impact               | T1490       | —            | Inhibit System Recovery                       |

---

## Hunt Query Logic

This query identifies suspicious executions of `cmd.exe` with command-line arguments related to the deletion of Rclone files and associated scripts. Such patterns are often seen in attacks where adversaries attempt to cover their tracks and prevent recovery.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name = "cmd.exe"
    and (
        action_process_image_command_line contains "del rclone"
        or action_process_image_command_line contains "del rcl.bat"
        or action_process_image_command_line contains "del nocmd.vbs"
    )
| fields _time, agent_hostname, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to run `cmd.exe` and delete files.
- **Required Artifacts:** Process creation logs, command-line arguments, file deletion logs.

---

## Considerations

- Investigate the user account and host context for the detected `cmd.exe` activity.
- Review for additional evidence removal actions, such as log clearing or shadow copy deletion.
- Correlate with other suspicious activity, such as data exfiltration or ransomware deployment.
- Check for signs of persistence or lateral movement.

---

## False Positives

False positives may occur if:

- Administrators are performing legitimate cleanup of Rclone or related scripts.
- Automated scripts or IT tools are used for software removal or maintenance.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the file deletions.
2. Review recent activity for signs of data exfiltration or ransomware.
3. Check for additional indicators of compromise or evidence removal.
4. Isolate affected systems if malicious activity is confirmed.
5. Restore deleted files and logs from backups if possible.

---

## References

- [MITRE ATT&CK: T1070.004 – Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004/)
- [MITRE ATT&CK: T1070.001 – Indicator Removal on Host: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect Rclone file deletion and evidence removal via Windows utilities |
