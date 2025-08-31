# Detection: EXE Payload - <8char>.exe under %APPDATA% executed via hidden PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-PHP-EXE-Payload-HiddenPS
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium (reduced by hidden window + random path)

---

## Hunt Analytics
Detects EXE payloads staged under randomized `%APPDATA%` subdirectories and launched via hidden PowerShell, observed with the CORNFLAKE.V3 PHP variant:

- File creation of `.exe` under `%APPDATA%\\Roaming\\[A-Za-z0-9]{8}\\<name>.exe`.
- Process execution of `powershell.exe`/`pwsh.exe` using hidden window switches (`-windowstyle hidden` or `-w h`) to run the staged EXE.

Pair with other PHP-variant hunts (staging of `%APPDATA%\\php`, HKCU Run pointing to `php.exe` + `config.cfg`) for multi-signal confidence.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                 |
|------------------------------|------------|--------------|-----------------------------------------------|
| TA0011 - Command and Control | T1105      |              | Ingress Tool Transfer                          |
| TA0002 - Execution           | T1059.001  | 001          | PowerShell                                    |
| TA0002 - Execution           | T1204.002  | 002          | Malicious File                                 |

---

## Hunt Query Logic
Surfaces either:
- File creation of EXEs in `%APPDATA%` randomized 8-char directories, or
- PowerShell executions that hide the window and invoke those EXEs by full path.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex XSIAM)

```xql
// Title: EXE payload staged to %APPDATA%<8char>\ and started via hidden PowerShell
// Description: Detects .exe creation under %APPDATA%[A-Za-z0-9]{8}\ and PowerShell invocation with -windowstyle hidden/-w h executing it.
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1059.001
// MITRE ATT&CK TTP ID: T1204.002

config case_sensitive = false   
| dataset = xdr_data   
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS   
  and (   
    (event_type = ENUM.FILE and action_file_name contains ".exe"   
      and action_file_path ~= "\\AppData\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9_\-]+\.exe")   
    or   
    (event_type = ENUM.PROCESS and action_process_image_name in ("powershell.exe","pwsh.exe")   
      and (action_process_image_command_line contains "-windowstyle hidden" or action_process_image_command_line contains "-w h")   
      and action_process_image_command_line ~= ".*\\AppData\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9_\-]+\.exe.*"   
    )   
  )   
| fields _time, agent_hostname, event_type,   
  action_file_name, action_file_path, action_file_sha256,   
  action_process_image_name, action_process_image_command_line,   
  actor_process_image_name, causality_actor_process_image_name,   
  event_id, agent_id, _product   
| sort desc _time   
```

Note: Regex escaping may need adjustment. The intent is to match `%APPDATA%\\Roaming\\<8 alnum>\\<name>.exe` and hidden PowerShell invocations thereof.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | File               | File Creation         |
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user writes to `%APPDATA%` and ability to run PowerShell.
- **Required Artifacts:** File creation telemetry and process creation telemetry with full command lines.

---

## Considerations
- You can further constrain by requiring the parent or causality chain to include `php.exe` from `%APPDATA%\\Roaming\\php\\` to attribute to the PHP variant.
- Consider also flagging when the EXE parent is `cmd.exe` or `powershell.exe` running with `-ExecutionPolicy Bypass`.

---

## False Positives
- Some legitimate updaters might transiently drop EXEs under `%APPDATA%`, but the hidden window execution pattern is uncommon. Add allowlists for known publishers as needed.

---

## Recommended Response Actions
1) Triage:
   - Review the writing process, file hash, and signature. Inspect PowerShell command line for additional parameters.
2) Contain:
   - Quarantine the EXE and isolate the host.
3) Eradicate:
   - Remove associated persistence (HKCU Run to `php.exe`) and delete `%APPDATA%` staged payloads.

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | EXE payload staged to random AppData dir and invoked via hidden PS.   |
