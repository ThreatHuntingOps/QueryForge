# Detection of PipeMagic ChatGPT Loader with AES Decryption Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-PipeMagic-ChatGPT-Loader-AES
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics
This hunt detects execution of PipeMagic loader samples masquerading as ChatGPT clients (`chatgpt.exe`). The loaders, implemented in Rust with Tokio/Tauri, decrypt embedded AES payloads at runtime using the `libaes` library, while presenting a fake ChatGPT interface. The detection emphasizes the executable name and a known campaign MD5 hash observed in attacks targeting Middle Eastern organizations and expanding globally.

Detected behaviors include:
- Process starts where the image name is `chatgpt.exe` and the file MD5 matches a known PipeMagic IOC.
- ChatGPT-named binaries executed from suspicious drop locations (Downloads, Temp, AppData, Public, ProgramData).
- Optional correlation with Azure `cloudapp` domains and subsequent memory/IPC activity consistent with PipeMagic.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                       |
|------------------------------|-------------|--------------|------------------------------------------------------|
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                       |
| TA0005 - Defense Evasion     | T1140       | —            | Deobfuscate/Decode Files or Information              |
| TA0005 - Defense Evasion     | T1027       | —            | Obfuscated/Compressed Files and Information          |
| TA0005 - Defense Evasion     | T1036.005   | —            | Masquerading: Match Legitimate Name or Location      |

Notes:
- Primary IOC: MD5 hash `7e6bf818519be0a20dbc9bcb9e5728c6` for `chatgpt.exe`.
- The loader leverages Rust (Tokio/Tauri) and `libaes` for AES decryption; expect in-memory payload staging and possible follow-on IPC (named pipes) or injection.

---

## Hunt Query Logic
Two complementary queries are provided:
- Query 1 detects execution of `chatgpt.exe` and/or a known MD5 hash associated with the PipeMagic loader.
- Query 2 flags `chatgpt.exe` started from common malware drop paths to raise confidence of malicious staging.

Correlate with network connections to Azure `cloudapp` domains and with subsequent named pipe creation or memory injection telemetry.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: PipeMagic ChatGPT Loader Detection
// Description: Detects execution of chatgpt.exe associated with PipeMagic campaigns, including known MD5 hash
// MITRE ATT&CK TTP ID: T1204.002
// MITRE ATT&CK TTP ID: T1140
// MITRE ATT&CK TTP ID: T1027

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and (action_process_image_name = "chatgpt.exe" 
         and action_file_md5 = "7e6bf818519be0a20dbc9bcb9e5728c6") 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, action_process_image_sha256, action_file_md5, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, event_id, agent_id, _product 
| sort desc _time 
```

```xql
// Title: ChatGPT Executables from Suspicious Locations
// Description: Detects chatgpt.exe execution from common malware drop locations
// MITRE ATT&CK TTP ID: T1204.002

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "chatgpt.exe" 
    and (action_process_image_path contains "\Downloads\" 
         or action_process_image_path contains "\Temp\" 
         or action_process_image_path contains "\AppData\" 
         or action_process_image_path contains "\Users\\Public\" 
         or action_process_image_path contains "\ProgramData\") 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, action_process_image_sha256, action_file_md5, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Collection of Windows process creation telemetry with full command-line and file hash metadata.
- **Required Artifacts:** Process events for `chatgpt.exe`, file hashes (MD5/SHA256), image paths, and parent process lineage.

---

## Considerations
- Validate whether `chatgpt.exe` is a legitimate application deployed by IT; most enterprises do not deploy a standalone ChatGPT binary.
- Combine with DNS/network telemetry for Azure `cloudapp` hosts and with named pipe or injection detections to raise confidence.
- Track additional hashes and filenames as the campaign evolves; consider fuzzy matching on PE metadata or signer where available.
- Watch for blank or non-functional UI windows that may indicate a decoy interface.

---

## False Positives
- Users may run third-party ChatGPT wrappers; verify publisher/signature and distribution source.
- Red team tooling may mimic the same filename and paths.

---

## Recommended Response Actions
1. Review `chatgpt.exe` binary metadata, signer, and compile time; compare against known-good baselines.
2. Quarantine or block the binary if unsigned/untrusted; collect the file for analysis.
3. Correlate with process lineage, named pipe activity, and memory indicators of AES-decrypted payloads.
4. Investigate outbound connections to Azure `cloudapp` domains and any subsequent C2 behavior.
5. Hunt for persistence mechanisms and lateral movement on impacted hosts.

---

## References
- MITRE ATT&CK: T1204.002 – User Execution: Malicious File https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK: T1140 – Deobfuscate/Decode Files or Information https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK: T1027 – Obfuscated/Compressed Files and Information https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location https://attack.mitre.org/techniques/T1036/005/

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-22 | Initial Detection | Hunt for PipeMagic ChatGPT loader (Tokio/Tauri, AES via libaes) with MD5 IOC and suspicious path query. |
