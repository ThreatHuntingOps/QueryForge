
# Detection of HazyBeacon Post-Exploitation Cleanup

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Cleanup-HazyBeacon
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt is designed to detect the final stage of the HazyBeacon attack: evidence removal. The query identifies the use of common command-line tools (`cmd.exe`, `powershell.exe`) to delete the specific payloads and artifacts associated with the attack from the `C:\ProgramData` directory. Detecting this cleanup activity is a strong indicator that a compromise has already occurred and the attacker is actively trying to cover their tracks to evade forensic investigation.

Detected behaviors include:
- Process execution of `cmd.exe` or `powershell.exe`.
- Command line containing a deletion command (`del` or `Remove-Item`).
- The target of the deletion command is one of the known HazyBeacon payload files or a `.zip` archive in the `ProgramData` path.

This technique is a key part of the Defense Evasion tactic.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0005 - Defense Evasion      | T1070       | T1070.004    | Indicator Removal on Host: File Deletion       |

---

## Hunt Query Logic

This query identifies post-exploitation cleanup by looking for:

- `PROCESS_START` events on Windows endpoints.
- The acting process is `cmd.exe` or `powershell.exe`.
- The command line includes `del` or `Remove-Item`.
- The command line also references one of the known HazyBeacon payload paths in `C:\ProgramData` or a `.zip` file, which is used for staging.

A match for this logic is a strong indicator that an attacker is performing cleanup actions on a compromised host.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: HazyBeacon Post-Exploitation File Deletion
// Description: Detects the deletion of HazyBeacon payloads and artifacts from the C:\ProgramData directory, indicating attacker cleanup activity.
// MITRE ATT&CK TTP ID: T1070.004

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and actor_process_image_name in ("cmd.exe", "powershell.exe")
    and (action_process_image_command_line contains "del " or action_process_image_command_line contains "Remove-Item")
    and (
        action_process_image_command_line contains "\ProgramData\7z.exe" or
        action_process_image_command_line contains "\ProgramData\igfx.exe" or
        action_process_image_command_line contains "\ProgramData\GoogleGet.exe" or
        action_process_image_command_line contains "\ProgramData\google.exe" or
        action_process_image_command_line contains "\ProgramData\GoogleDrive.exe" or
        action_process_image_command_line contains "\ProgramData\GoogleDriveUpload.exe" or
        action_process_image_command_line contains "\ProgramData\Dropbox.exe" or
        action_process_image_command_line contains ".zip"
    )
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

- **Required Permissions:** The attacker must have permissions to delete files in the `C:\ProgramData` directory.
- **Required Artifacts:** Endpoint logs capturing process creation events with full command-line arguments.

---

## Considerations

- An alert from this query is a "trailing indicator," meaning the primary malicious activities (collection, exfiltration) have likely already occurred.
- The investigation should immediately pivot to a full incident response to determine the scope and impact of the breach.
- Check for file deletion events in addition to process creation events if your EDR provides them, as this can offer more direct evidence.

---

## False Positives

- False positives are very low. Legitimate scripts or users should not be deleting these specific, maliciously-named files from the `C:\ProgramData` directory.

---

## Recommended Response Actions

1.  Isolate the affected endpoint immediately to preserve any remaining forensic artifacts.
2.  Trigger a full incident response procedure.
3.  Assume the host was fully compromised and data was exfiltrated. The primary goal is to determine *what* was taken.
4.  Review all preceding activity on the host to reconstruct the entire attack chain.
5.  Expand the investigation to other hosts to check for similar activity, as the attacker may have moved laterally.

---

## References

- [Unit 42: HazyBeacon: An In-Depth Look at a New Windows Backdoor for Novel C2 Communication](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)
- [MITRE ATT&CK: T1070.004 – Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect the cleanup phase of the HazyBeacon attack.                   |
