# Detection of JS Copy to Public Downloads via cmd.exe (edriophthalma.js)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Cmd-Copy-JS-PublicDownloads-edriophthalma
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects `cmd.exe` executions that copy JavaScript files (e.g., `*.js`) into the public downloads directory as `C:\\Users\\Public\\Downloads\\edriophthalma.js`. This behavior matches staging steps observed in .NET delivery chains where a JS payload is dropped to a world-readable path for later execution by `wscript.exe`/`cscript.exe`, scheduled tasks, or additional loaders. Characteristics include:

- **Command shell copy operation** using `cmd.exe /C copy`
- **Targeted destination** of `C:\\Users\\Public\\Downloads\\edriophthalma.js` (or references to `edriophthalma.js`)
- **Early-stage persistence or payload staging** prior to execution

---

## ATT&CK Mapping

| Tactic                     | Technique  | Subtechnique | Technique Name                                                     |
|---------------------------|------------|--------------|--------------------------------------------------------------------|
| TA0002 - Execution        | T1059.003  | —            | Command and Scripting Interpreter: Windows Command Shell           |
| TA0002 - Execution        | T1204.002  | —            | User Execution: Malicious File                                     |
| TA0003 - Persistence      | T1547.001  | —            | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder* |

> *Included due to common linkage in observed chains where the staged JS is later wired into autorun mechanisms. Adjust during triage if no persistence is found.

---

## Hunt Query Logic

This query identifies suspicious copy operations where `cmd.exe` performs a file copy of JavaScript files into `C:\\Users\\Public\\Downloads\\edriophthalma.js` (or references that filename). It prioritizes **high-fidelity** matches on `cmd.exe` and `/c copy` semantics, plus destination filename indicators.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: JS Copy to Public Downloads via cmd.exe
// Description: Detects cmd.exe copying JS files to C:\Users\Public\Downloads\edriophthalma.js or similar copy commands indicating staging.
// MITRE ATT&CK TTP ID: T1547.001 (persistence linkage), T1204.002 (User Execution), T1059.003 (Windows Command Shell)

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
    and event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
// Ensure copy semantics via cmd.exe
    and action_process_image_name = "cmd.exe"
    and (
        action_process_image_command_line contains "/c copy "
        or action_process_image_command_line contains " copy "
    )
// Targeted filename or destination indicators
    and (
        action_process_image_command_line contains "c:\users\\public\downloads\edriophthalma.js"
        or action_process_image_command_line contains "edriophthalma.js"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line,
        actor_process_image_name, actor_process_command_line, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** Ability to launch `cmd.exe` and write to `C:\\Users\\Public\\Downloads`.
- **Required Artifacts:** Process creation logs including full command-line, and (optional) file creation events for the target path.

---

## Considerations

- Triaging should confirm whether the JS file is later executed (e.g., `wscript.exe`/`cscript.exe`), referenced by scheduled tasks, or invoked by other loaders.
- Public directories are shared; dropping payloads here may facilitate multi-user access and evasion of per-user profile monitoring.
- Review the **parent process**, **user context**, and **original file source** (email, browser download, script runner).

---

## False Positives

Potential false positives can occur if:

- Administrative scripts or deployment tools copy JavaScript helpers to shared locations as part of legitimate workflows.
- Developers or IT staff use `cmd.exe /C copy` to stage web assets temporarily (rare on endpoints).

Lower false positives by scoping to **non-admin users**, **unusual parent processes**, and **off-hours activity**.

---

## Recommended Response Actions

1. **Isolate** or contain the endpoint if the activity is suspicious.
2. **Acquire the file** `C:\\Users\\Public\\Downloads\\edriophthalma.js`, compute hash, and submit for static/dynamic analysis.
3. **Hunt for execution**: search for subsequent `wscript.exe`/`cscript.exe` launches referencing this path/filename.
4. **Check persistence**: inspect Scheduled Tasks, Run/RunOnce keys, Startup folders referencing the staged JS.
5. **Trace lineage**: review browser/download logs and email security for the original delivery vector.
6. **Block/clean up**: remove the staged file if malicious and add detections for similar copy patterns.

---

## References

- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-19 | Initial Detection | Detects cmd.exe copy of JS to Public Downloads as edriophthalma.js. |
