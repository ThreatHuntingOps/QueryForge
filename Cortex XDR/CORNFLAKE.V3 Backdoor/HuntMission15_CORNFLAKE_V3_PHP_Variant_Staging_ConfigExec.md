# Detection: CORNFLAKE.V3 PHP Variant - Staging, C2, Payload Handling, and Persistence

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-PHP-Variant-Staging-Exec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium (reduced with full command-line and path constraints)

---

## Hunt Analytics
This hunt focuses on the newly observed PHP-based CORNFLAKE.V3 variant and its staging/execution behavior:

- Staging: PHP runtime downloaded (commonly from `windows.php[.]net`), extracted to `%APPDATA%\\php`, then executed.
- Execution: `php.exe` invoked from `%APPDATA%\\Roaming\\php\\` to run `config.cfg`, commonly with flags `-d extension=zip` and `-d extension_dir=ext`, sometimes followed by a trailing ` 1` argument indicative of self-respawn/hand-off logic.
- Subsequent activity can include C2 via Cloudflare Tunnel hosts and payload handling that writes/executes disguised files under `%APPDATA%\\<rand_8_char>\\` with atypical extensions.

Pair these detections with earlier Node-based hunts to cover cross-variant behaviors across toolchains.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                         |
|------------------------------|------------|--------------|----------------------------------------|
| TA0011 - Command and Control | T1105      |              | Ingress Tool Transfer                  |
| TA0002 - Execution           | T1059      |              | Command and Scripting Interpreter      |

---

## Hunt Query Logic
Detects file artifacts under `%APPDATA%\\Roaming\\php\\` and process executions of `php.exe` from that directory running `config.cfg` with `-d extension=zip` and `-d extension_dir=ext` flags (and optional trailing ` 1`).

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: PHP staged to %APPDATA%\php and executed with -d extension flags
// Description: Detects download/extraction of PHP into AppData\Roaming\php and execution of php.exe running config.cfg with -d extension=zip -d extension_dir=ext and trailing " 1" argument.
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1059

config case_sensitive = false  
| dataset = xdr_data  
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS  
  and (  
    // File artifacts and process execution  
    (event_type = ENUM.FILE and action_file_path contains "\AppData\Roaming\php\")  
    or  
    (event_type = ENUM.PROCESS and action_process_image_name = "php.exe" and action_process_image_path contains "\AppData\Roaming\php\"  
      and action_process_image_command_line contains " -d extension=zip "  
      and action_process_image_command_line contains " -d extension_dir=ext "  
      and action_process_image_command_line contains "\AppData\Roaming\php\config.cfg"  
    )  
  )  
| fields _time, agent_hostname, event_type,  
  action_file_name, action_file_path, action_file_sha256,  
  action_process_image_name, action_process_image_path, action_process_image_command_line,  
  actor_process_image_name, actor_process_image_path, actor_process_command_line,  
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line,  
  event_id, agent_id, _product  
| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | File               | File Creation         |
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user sufficient for `%APPDATA%` writes and execution.
- **Required Artifacts:** File and process telemetry with full paths and command-line arguments.

---

## Considerations
- Version/path variations: Actors may use different PHP versions; keep the `%APPDATA%\\Roaming\\php\\` anchor but be flexible with filenames.
- Trailing ` 1` argument: If observed in your telemetry, add an additional contains " 1" to increase fidelity.
- Cross-variant linkage: Monitor for subsequent behavior indicating payload staging/execution, potential Node download (e.g., v21.7.3), and persistence creation under HKCU Run with randomized value names pointing to `php.exe` and `config.cfg`.

---

## False Positives
- Legitimate portable PHP usage under `%APPDATA%` is uncommon but possible; validate parent process, user context, and presence of config flags.

---

## Recommended Response Actions
1) Triage:
   - Review `php.exe` command lines and the contents/hashes of files under `%APPDATA%\\Roaming\\php\\`.
2) Containment:
   - Isolate host; block outbound C2 if Cloudflare Tunnel indicators are present.
3) Eradication:
   - Remove staged PHP runtime and any associated persistence (HKCU Run entries referencing `php.exe` + `config.cfg`).

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | PHP staged to %APPDATA% and executed with config.cfg and extension flags. |
