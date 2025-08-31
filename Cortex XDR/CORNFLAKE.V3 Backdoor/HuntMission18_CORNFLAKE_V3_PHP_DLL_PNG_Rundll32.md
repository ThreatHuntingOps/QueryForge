# Detection: DLL Payload - <8char>.png Executed via rundll32.exe

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-PHP-DLL-PNG-Rundll32
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low (PNG path + rundll32 execution)

---

## Hunt Analytics
Detects DLL masquerading as a PNG dropped under randomized `%APPDATA%` subdirectories and executed via `rundll32.exe`, observed in the CORNFLAKE.V3 PHP variant:

- File creation of `.png` under `%APPDATA%\\Roaming\\[A-Za-z0-9]{8}\\<name>.png`.
- Subsequent `rundll32.exe` invocation whose command line references that `.png` path (DLL masquerade).

Pair with other PHP-variant hunts (PHP staging and persistence) and Node-variant hunts for comprehensive coverage.

---

## ATT&CK Mapping

| Tactic                     | Technique  | Subtechnique | Technique Name                                  |
|---------------------------|------------|--------------|-------------------------------------------------|
| TA0005 - Defense Evasion  | T1218.011  | 011          | Signed Binary Proxy Execution: Rundll32         |
| TA0005 - Defense Evasion  | T1036      |              | Masquerading                                    |
| TA0011 - Command & Control| T1105      |              | Ingress Tool Transfer                           |

---

## Hunt Query Logic
Surfaces either:
- `.png` file writes to randomized AppData subfolders, or
- `rundll32.exe` processes that reference such `.png` paths on their command line.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex XSIAM)

```xql
// Title: DLL payload disguised as .png invoked via rundll32.exe
// Description: Detects .png writes under %APPDATA%<8char>\ then rundll32.exe referencing a .png path (DLL masquerade).
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1218.011
// MITRE ATT&CK TTP ID: T1036

config case_sensitive = false   
| dataset = xdr_data   
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS   
  and (   
    (event_type = ENUM.FILE and action_file_name contains ".png"   
      and action_file_path ~= "\\AppData\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9_\-]+\.png")   
    or   
    (event_type = ENUM.PROCESS and action_process_image_name = "rundll32.exe"   
      and action_process_image_command_line ~= ".*\\AppData\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9_\-]+\.png.*"   
    )   
  )   
| fields _time, agent_hostname, event_type, action_file_name, action_file_path,   
  action_process_image_name, action_process_image_path, action_process_image_command_line,   
  actor_process_image_name, causality_actor_process_image_name,   
  event_id, agent_id, _product   
| sort desc _time    
```

Note: The regex is intended to match `%APPDATA%\\Roaming\\<8 alnum>\\<name>.png` references.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | File               | File Creation         |
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user-level writes to `%APPDATA%` and ability to execute `rundll32.exe`.
- **Required Artifacts:** File creation telemetry and process command-line visibility.

---

## Considerations
- You may add lineage constraints tying the `rundll32.exe` or the write activity back to `php.exe` to strengthen attribution to this variant.
- If `.dll` masquerades use other extensions (`.jpg`, `.gif`), extend the regex accordingly.

---

## False Positives
- Rare; legitimate `rundll32.exe` should not reference `.png` files. Validate publisher and signedness if needed.

---

## Recommended Response Actions
1) Triage:
   - Inspect the written `.png` file; compute hash and check for PE headers.
2) Contain:
   - Quarantine the file and block the `rundll32.exe` command line pattern.
3) Eradicate:
   - Remove associated persistence and staged runtimes (e.g., `%APPDATA%\\Roaming\\php`).

---

## Version History

| Version | Date       | Impact              | Notes                                                                       |
|---------|------------|---------------------|-----------------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | DLL masquerade as .png, invoked via rundll32.exe from randomized AppData.  |
