# Detection: CMD Payload - Inline cmd/PowerShell Spawned from php.exe

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-PHP-InlineCmdPs
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium (reduced by php.exe lineage in %APPDATA%)

---

## Hunt Analytics
Detects inline command execution spawned by the PHP-based CORNFLAKE.V3 variant:

- `php.exe` from `%APPDATA%\\Roaming\\php\\` spawns `cmd.exe` with `/d /s /c` or `/c`, or PowerShell (`powershell.exe`/`pwsh.exe`) with `-c` to run inline commands.
- Often used for quick tasking such as reconnaissance or launching staged payloads.

Correlate with PHP staging and persistence hunts for stronger attribution.

---

## ATT&CK Mapping

| Tactic              | Technique  | Subtechnique | Technique Name                           |
|---------------------|------------|--------------|------------------------------------------|
| TA0002 - Execution  | T1059.003  | 003          | Command and Scripting Interpreter: Windows Command Shell |
| TA0002 - Execution  | T1059.001  | 001          | Command and Scripting Interpreter: PowerShell |

---

## Hunt Query Logic
Flags `cmd.exe` or PowerShell processes that execute inline commands when their parent/causal lineage points to `%APPDATA%\\Roaming\\php\\php.exe`.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex XSIAM)

```xql
// Title: Inline command execution (cmd/PowerShell) spawned by php.exe
// Description: Finds cmd.exe /d /s /c “…” or powershell.exe -c “…” where parent/lineage includes %APPDATA%\php\php.exe.
// MITRE ATT&CK TTP ID: T1059.003
// MITRE ATT&CK TTP ID: T1059.001

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
  and event_type = ENUM.PROCESS 
  and action_process_image_name in ("cmd.exe","powershell.exe","pwsh.exe") 
  and ( 
    action_process_image_command_line contains "/c " 
    or action_process_image_command_line contains " -c " 
  ) 
  and ( 
    actor_process_image_path contains "\AppData\Roaming\php\php.exe" 
    or causality_actor_process_image_path contains "\AppData\Roaming\php\php.exe" 
  ) 
| fields _time, agent_hostname, actor_effective_username, 
  action_process_image_name, action_process_image_command_line, 
  actor_process_image_name, actor_process_image_path, 
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line, 
  event_id, agent_id, _product 
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user privileges; requires process creation telemetry with command lines and lineage.

---

## Considerations and Tuning
- Add additional filters for hidden window usage (`-windowstyle hidden` or `-w h`) if observed.
- If actors switch to `cmd.exe /d /s /c`, optionally add a contains " /d " and " /s " for higher precision.

---

## False Positives
- Rare portable PHP tooling could spawn shells; the `%APPDATA%` php lineage plus inline command flags is atypical for benign usage.

---

## Recommended Response Actions
1) Triage the inline command payload and user context.
2) Correlate with PHP staging and HKCU Run persistence entries.
3) Contain and eradicate: remove `%APPDATA%\\Roaming\\php` runtime and related artifacts.

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | Inline cmd/PowerShell spawned from php.exe in %APPDATA%.              |
