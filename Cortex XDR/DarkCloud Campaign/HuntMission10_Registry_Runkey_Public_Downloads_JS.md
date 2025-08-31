# Detection of HKCU Run Key Pointing to Public Downloads JS (edriophthalma.js)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Registry-RunKey-PublicDownloadsJS
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium

---

## Hunt Analytics

This hunt detects suspicious registry modifications where a Run key is created or updated under:

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

with values pointing to JavaScript files in `C:\\Users\\Public\\Downloads` or explicitly referencing `edriophthalma.js`. Attackers commonly use this technique to establish persistence after initially dropping a staged JavaScript payload. Indicators include:

- Registry Run key values invoking `wscript.exe` or `cmd.exe` to execute a `.js` file
- References to **public downloads paths** or the specific staged file `edriophthalma.js`
- **Persistence via autorun execution** triggered upon user logon

---

## ATT&CK Mapping

| Tactic                  | Technique  | Subtechnique | Technique Name                                              |
|-------------------------|------------|--------------|-------------------------------------------------------------|
| TA0003 - Persistence    | T1547.001  | —            | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |

---

## Hunt Query Logic

This query identifies suspicious **registry modifications** where Run keys reference either `edriophthalma.js`, a generic JS staged in `Public\\Downloads`, or invocations via `wscript.exe`/`cmd.exe` that load such files. It focuses on HKCU-level keys, which are attacker-preferred for per-user persistence.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: HKCU Run Key pointing to Public Downloads JS
// Description: Detect creation/modification of HKCU Run keys that reference edriophthalma.js or JS files in Public Downloads.
// MITRE ATT&CK TTP ID: T1547.001 (Boot or Logon Autostart Execution)

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
    and event_type = ENUM.REGISTRY
| filter action_registry_key_name contains "\software\microsoft\windows\currentversion\run"
// Value data contains reference to staged JS or execution engine
    and (
        action_registry_value_name contains "edriophthalma.js"
        or action_registry_value_name contains "public\downloads"
        or action_registry_value_name contains "wscript.exe"
        or action_registry_value_name contains "c:\users\public\downloads\"
    )
| fields _time, agent_hostname, actor_effective_username, action_registry_key_name, action_registry_value_name, 
         event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Registry           | Registry Key Modification |

---

## Execution Requirements

- **Required Permissions:** Ability to modify HKCU registry keys
- **Required Artifacts:** Registry modification logs with value name and data fields

---

## Considerations

- Keys under HKCU\\...\\Run are executed on **user logon** – correlate with process creation events to confirm execution.
- Ensure the suspicious JS file exists at the referenced location.
- Investigate whether parent activity (e.g., dropped by prior loader or phishing delivery) aligns with broader campaign activity.

---

## False Positives

False positives may occur when:

- Legitimate applications store auto-start configuration pointing to scripts under unusual directories (rare).
- Internal IT automation registers JS-based utilities as Run entries.

False positives can be reduced by validating whether the **referenced file** is signed, known-good, or originates from a trusted directory.

---

## Recommended Response Actions

1. Inspect the **Run key entry** for legitimacy and review the file path it references.
2. Retrieve and analyze the referenced JS payload (`edriophthalma.js` or similar).
3. Hunt for **prior process execution** (cmd.exe copy, JS staging) that established this persistence.
4. Check for **subsequent executions** of `wscript.exe`/`cscript.exe` referencing the staged file.
5. Remove the malicious registry entry and staged file if confirmed malicious.
6. Monitor for reinfection attempts.

---

## References

- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-19 | Initial Detection | Detects registry Run key persistence referencing JS in Public Downloads. |
