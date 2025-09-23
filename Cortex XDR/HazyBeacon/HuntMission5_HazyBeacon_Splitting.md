
# Detection of Data Staging via Archive Splitting

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-ArchiveSplitting-HazyBeacon
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a specific and high-fidelity data staging behavior used by the HazyBeacon threat actor. The query identifies the execution of `7z.exe` from the non-standard `C:\ProgramData` directory with the `-v` command-line flag. This flag instructs 7-Zip to create split-volume archives, a technique used by attackers to break large files into smaller chunks to bypass network egress controls or detection based on file size. This action is a strong indicator that an attacker has already collected and archived data and is now preparing it for exfiltration.

Detected behaviors include:
- Process execution of `7z.exe` from `C:\ProgramData`.
- Command line containing the `-v` flag for volume splitting.

This technique is a key part of the Collection and Staging phases of an attack.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0009 - Collection           | T1560       | T1560.001    | Archive Collected Data: Archive via Utility    |
| TA0009 - Collection           | T1074       | T1074.001    | Data Staged: Local Data Staging                |

---

## Hunt Query Logic

This query identifies the specific data staging technique by looking for:

- `PROCESS_START` events on Windows endpoints.
- The process image path is exactly `C:\ProgramData\7z.exe`.
- The command line contains the string ` -v`, indicating volume creation.

A match for this logic is a strong indicator of malicious data staging activity.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Data Staging via 7-Zip Volume Creation
// Description: Detects the use of 7z.exe from C:\ProgramData with the "-v" flag to split files into smaller volumes, a specific TTP used by the HazyBeacon actor for data staging.
// MITRE ATT&CK TTP ID: T1560.001
// MITRE ATT&CK TTP ID: T1074.001

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_path = "C:\ProgramData\7z.exe"
    and action_process_image_command_line contains " -v"
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, event_id, agent_id, _product
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The attacker must have permissions to write and execute files in the `C:\ProgramData` directory.
- **Required Artifacts:** Endpoint logs capturing process creation events with full command-line arguments.

---

## Considerations

- Upon alert, examine the full command line to identify the source archive and the size of the volumes being created (e.g., `-v200m`).
- Look for the creation of multiple archive files with sequential extensions (e.g., `.001`, `.002`).
- This activity will almost certainly be preceded by the execution of `igfx.exe` and the creation of a large, single archive file.

---

## False Positives

- False positives are extremely unlikely. The combination of `7z.exe` running from `C:\ProgramData` and using the volume-splitting feature is a highly specific and anomalous behavior.

---

## Recommended Response Actions

1.  Isolate the affected endpoint immediately.
2.  Identify and acquire all parts of the split archive for forensic analysis to determine the scope of the data breach.
3.  Investigate the host for the full HazyBeacon attack chain.
4.  Remediate the host by removing all malicious files and persistence mechanisms.

---

## References

- [Unit 42: HazyBeacon: An In-Depth Look at a New Windows Backdoor for Novel C2 Communication](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)
- [MITRE ATT&CK: T1560.001 – Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)
- [MITRE ATT&CK: T1074.001 – Data Staged: Local Data Staging](https://attack.mitre.org/techniques/T1074/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect the specific TTP of splitting archives into smaller volumes for exfiltration. |
