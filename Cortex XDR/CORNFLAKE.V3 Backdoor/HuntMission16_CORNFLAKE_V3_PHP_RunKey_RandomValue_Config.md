# Detection: PHP Persistence via HKCU Run (Random Value) -> php.exe config.cfg

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-PHP-RunKey-RandomValue
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low (specific path + php.exe + config.cfg)

---

## Hunt Analytics
Detects persistence for the PHP-based CORNFLAKE.V3 variant using HKCU Run entries:

- Creation/modification of `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` values whose data launches `%APPDATA%\\Roaming\\php\\php.exe` with a path to `config.cfg`.
- Value name is randomized (unlike the Node variant's `ChromeUpdater`).
- Complements the staging detection for `%APPDATA%\\Roaming\\php\\` and C2/payload handling hunts.

---

## ATT&CK Mapping

| Tactic                 | Technique  | Subtechnique | Technique Name                          |
|-----------------------|------------|--------------|-----------------------------------------|
| TA0003 - Persistence  | T1547.001  | 001          | Registry Run Keys/Startup Folder        |

---

## Hunt Query Logic
Flags HKCU Run registry events where the value data references `%APPDATA%\\Roaming\\php\\php.exe` and `config.cfg`, regardless of the value name.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex XSIAM)

```xql
// Title: PHP persistence via HKCU Run (random value) -> php.exe config.cfg
// Description: Detects creation/modification of HKCU\Software\Microsoft\Windows\CurrentVersion\Run entries whose value data invokes %APPDATA%\php\php.exe and a path to config.cfg. Value name is random (unlike ChromeUpdater).
// MITRE ATT&CK TTP ID: T1547.001

config case_sensitive = false  
| dataset = xdr_data  
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS  
  and event_type = ENUM.REGISTRY  
  and action_registry_key_name contains "\Software\Microsoft\Windows\CurrentVersion\Run"  
  and action_registry_value_name contains "\AppData\Roaming\php\php.exe"  
  and action_registry_value_name contains "\AppData\Roaming\php\config.cfg"  
| fields _time, agent_hostname, actor_effective_username, 
  actor_process_image_name, actor_process_image_path, actor_process_command_line,  
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line,  
  event_id, agent_id, _product  
| sort desc _time
```

Note: Some tenants log Run key changes as FILE or hybrid events with separate fields for value data. Adjust field names accordingly (e.g., `action_registry_value_data`).

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Registry           | Registry Key/Value Modification |

---

## Execution Requirements
- **Required Permissions:** Standard user; HKCU Run does not need admin.
- **Required Artifacts:** Registry modification telemetry capturing key path, value name, and value data.

---

## Considerations and Tuning
- Value name is randomized; do not filter on specific names.
- Consider correlating with preceding PHP staging events and subsequent `php.exe` executions on user logon.
- If `config.cfg` path varies, loosen matching to contains `\\AppData\\Roaming\\php\\config`.

---

## False Positives
- Portable PHP tools rarely set HKCU Run to `%APPDATA%\\php\\php.exe` with `config.cfg`. Validate publisher, parent process lineage, and user context.

---

## Recommended Response Actions
1) Confirm persistence:
   - Capture the registry value data and verify it launches `php.exe` with `config.cfg`.
2) Contain:
   - Remove the Run key entry, isolate host if suspicious C2 present.
3) Eradicate:
   - Delete `%APPDATA%\\Roaming\\php\\` runtime and any associated payloads.

---

## Version History

| Version | Date       | Impact              | Notes                                                       |
|---------|------------|---------------------|-------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | HKCU Run persistence to php.exe with config.cfg (random name). |
