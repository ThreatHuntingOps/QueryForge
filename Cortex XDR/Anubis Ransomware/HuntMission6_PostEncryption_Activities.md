# Detection of Anubis Ransomware: Icon and Wallpaper Dropping, File Extension Changes, and Ransom Note Creation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnubisPostEncryption
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Extremely Low

---

## Hunt Analytics

This hunt detects behaviors associated with Anubis ransomware’s post-encryption activities, including dropping custom icons and wallpaper images to `C:\ProgramData`, changing file extensions to `.anubis.`, attempting to set a custom wallpaper, and creating a ransom note named `RESTORE FILES.html`. These actions are strong indicators of ransomware activity and can help surface infections in progress or after the fact. The detection logic combines file write and process execution events for high-fidelity alerting.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1491       | —            | Defacement                                    |
| TA0040 - Impact              | T1490       | —            | Inhibit System Recovery                       |
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |
| TA0040 - Impact              | T1565.002   | —            | Data Manipulation: Stored Data Manipulation   |

---

## Hunt Query Logic

This query identifies:
- File write events where `icon.ico`, `wall.jpg`, or `RESTORE FILES.html` are created, or files are written with the `.anubis.` extension
- Process execution events where a process attempts to change the desktop wallpaper using `wall.jpg` and references `Control Panel\Desktop` in the command line

These behaviors are highly suspicious and rarely seen in legitimate activity, making them strong indicators of ransomware infection and post-encryption impact.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious Use of ProgramData Icon/Wallpaper or Ransomware Artifacts
// Description: Detects processes referencing suspicious files in ProgramData (icon.ico, wall.jpg, RESTORE FILES.html, .anubis.) and command lines referencing wall.jpg or desktop control panel, which may indicate ransomware or system modification activity.
// MITRE ATT&CK TTP ID: T1491

config case_sensitive = false 
| dataset = xdr_data 
| filter (event_type = ENUM.FILE or event_type = ENUM.PROCESS)
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_path = "C:/ProgramData/icon.ico"
        or action_process_image_path = "C:/ProgramData/wall.jpg"
        or action_process_image_path contains "/RESTORE FILES.html"
        or action_process_image_path contains ".anubis."
    )
    and (
        action_process_image_command_line contains "wall.jpg"
        or action_process_image_command_line contains "Control Panel/Desktop"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |
---

## Execution Requirements

- **Required Permissions:** User or attacker must have write access to `C:\ProgramData` and the ability to modify desktop settings.
- **Required Artifacts:** File creation logs, process creation logs, and desktop configuration changes.

---

## Considerations

- Correlate with other ransomware behaviors, such as file encryption or shadow copy deletion.
- Review the process tree and parent process for initial access vectors.
- Investigate the timing and frequency of ransom note and wallpaper changes.
- Look for additional indicators of post-encryption impact, such as user notifications or system modifications.

---

## False Positives

False positives are extremely rare, but may occur if:
- Custom IT or branding tools deploy icons or wallpapers to `C:\ProgramData` (uncommon).
- Legitimate scripts or applications create files with `.anubis.` extensions (very rare).

---

## Recommended Response Actions

1. Isolate the affected endpoint immediately to prevent further impact.
2. Investigate the process tree and user context for signs of compromise.
3. Review for additional ransomware behaviors, such as file encryption or privilege escalation.
4. Collect forensic artifacts (memory, disk, logs) for further analysis.
5. Initiate incident response and recovery procedures as soon as possible.
6. Notify impacted users and IT staff of potential ransomware infection.

---

## References

- [MITRE ATT&CK: T1491 – Defacement](https://attack.mitre.org/techniques/T1491/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1565.002 – Data Manipulation: Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/002/)
- [Anubis: A Closer Look at an Emerging Ransomware with Built-in Wiper](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-24 | Initial Detection | Created hunt query to detect Anubis ransomware icon/wallpaper dropping, file extension changes, and ransom note creation |
