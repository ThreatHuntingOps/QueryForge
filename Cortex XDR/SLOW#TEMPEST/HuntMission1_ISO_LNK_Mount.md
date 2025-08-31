# Detection of ISO-Based LNK Execution via Mounted Devices

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Cortex-ISO-LNK-Mount
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium

---

## Hunt Analytics

This hunt detects a multi-stage attack chain involving ISO file creation, registry modification of mounted drives, and execution of suspicious `.pdf.lnk` files from the mounted device using `explorer.exe`. Attackers often leverage ISO-based malspam or droppers to deliver LNK payloads, which are then executed by the user, leading to initial access or further malware delivery. The query correlates ISO file creation, registry changes for new drive mounts, and LNK file execution to identify this attack pattern.

---

## ATT&CK Mapping

| Tactic                | Technique ID   | Technique Name                                 |
|-----------------------|---------------|------------------------------------------------|
| Initial Access        | T1566.001     | Phishing: Spearphishing Attachment             |
| Execution             | T1204         | User Execution                                 |
| Execution             | T1204.002     | User Execution: Malicious File                 |
| Execution             | T1218.011     | Signed Binary Proxy Execution: Rundll32        |
| Defense Evasion       | T1036         | Masquerading                                   |

---

## Hunt Query Logic

This query identifies suspicious activity where:

- An ISO file is created on the system.
- The registry is modified to mount a new drive (MountedDevices).
- A `.pdf.lnk` file is executed from the mounted drive using `explorer.exe` within a short time window.

Such patterns are often associated with malspam campaigns or ISO droppers delivering LNK-based payloads for initial access.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: ISO-Based LNK Execution via Mounted Devices
// Description: Correlates ISO file creation, registry modification of mounted drives, and suspicious .pdf.lnk file execution from the mounted drive using explorer.exe. Detects possible Malspam or ISO dropper leading to LNK payloads.

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE 
| filter action_registry_key_name contains "HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices" 
| filter actor_effective_user_sid = "S-1-5-18" 
| alter driveLetterMount = arrayindex(regextract(action_registry_value_name,"\DosDevices\([A-Z])"),0) 
| filter driveLetterMount != "" and driveLetterMount != NULL 
| fields _time as timeMount, agent_hostname, actor_process_image_name, action_registry_key_name, actor_process_instance_id,driveLetterMount 
| join type = inner conflict_strategy = both ( dataset = xdr_data 
| filter event_type = ENUM.FILE | filter action_file_extension = "iso" 
| fields _time as timeCreateImgeFile, agent_hostname, event_type, event_sub_type, action_file_name as iso_file_name, action_file_path as iso_file_path, actor_effective_username, action_file_sha256 as iso_sha256,actor_process_instance_id,actor_process_image_path,causality_actor_process_image_path, action_file_signature_status ) as file file.agent_hostname = agent_hostname 
| alter diff = timestamp_diff(timeMount ,timeCreateImgeFile,"SECOND") 
| filter diff >= 0 and diff < 60 | join type = inner conflict_strategy = both (dataset = xdr_data 
| filter event_type = ENUM.FILE and (event_sub_type in(FILE_WRITE,FILE_CREATE_NEW,ENUM.FILE_OPEN)) 
| filter action_file_extension = "lnk" and action_file_path = "*.pdf.lnk" 
| alter File_Driver_Letter = arrayindex(regextract(action_file_path,"^([A-Za-z]):\"),0) 
| filter actor_process_image_name = "explorer.exe" and causality_actor_process_image_name = "explorer.exe" 
| fields _time as timeExecuted, agent_hostname, event_type, event_sub_type, action_file_name as lnk_file_name, action_file_path as lnk_file_path, actor_effective_username, action_file_sha256 as lnk_sha256, File_Driver_Letter ) as proc proc.agent_hostname = agent_hostname | alter diff2 = timestamp_diff(timeExecuted,timeMount,"SECOND") 
| filter diff2 >= 0 and diff2 < 120 
| filter File_Driver_Letter = driveLetterMount 
| fields timeCreateImgeFile,timeMount, timeExecuted, agent_hostname, actor_effective_username, iso_file_name, iso_file_path, iso_sha256, lnk_file_name, lnk_file_path, lnk_sha256, actor_process_image_path 
| comp values(timeExecuted) as time,values(actor_process_image_path) as actor_process_image_path,values(actor_effective_username) as actor_effective_username,values(agent_hostname) as agent_hostname, values(iso_file_name) as iso_file_name,values(iso_sha256) as iso_sha256, values(lnk_file_name) as lnk_file_name, values(lnk_file_path) as lnk_file_path,values(lnk_sha256) as lnk_sha256 by iso_file_path
```

---

## Data Sources

| Log Provider   | Event Name   | ATT&CK Data Source      | ATT&CK Data Component                |
|----------------|--------------|-------------------------|--------------------------------------|
| Cortex XSIAM   | xdr_data     | File, Registry, Process | File Creation, Registry Modification, Process Execution |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to mount ISO files and execute LNK payloads.
- **Required Artifacts:** ISO files, registry modification logs, LNK file execution logs, process creation logs.

---

## Considerations

- Investigate the source and contents of the ISO and LNK files for malicious code.
- Review the parent process and user context for signs of phishing or malspam delivery.
- Correlate with email gateway or web proxy logs for initial delivery vectors.
- Check for additional payloads or persistence mechanisms dropped post-execution.

---

## False Positives

False positives may occur if:

- Legitimate software distribution uses ISO files and LNK shortcuts as part of installation.
- Administrative or automation tasks mount ISOs and execute LNKs in a controlled manner.

---

## Recommended Response Actions

1. Investigate the ISO and LNK files and their origins.
2. Analyze the executed LNK payload for suspicious or obfuscated code.
3. Review user and process activity for further malicious behavior.
4. Isolate affected systems if malicious activity is confirmed.
5. Remove any unauthorized files or payloads from the system.

---

## References

- [MITRE ATT&CK: T1204 – User Execution](https://attack.mitre.org/techniques/T1204/)
- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1218.011 – Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK: T1036 – Masquerading](https://attack.mitre.org/techniques/T1036/)
- [Unit 42: Evolving Tactics of SLOW#TEMPEST: A Deep Dive Into Advanced Malware Techniques](https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.1     | 2025-07-15 | Enhanced Mapping  | Added additional ATT&CK mappings for phishing, masquerading, and signed binary proxy exec   |
| 1.0     | 2025-07-15 | Initial Detection | Created hunt query to detect ISO-based LNK execution via mounted devices                   |
