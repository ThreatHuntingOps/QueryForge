# Detection of Fake Chrome RAT Dropping Persistence in Startup via PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-FakeChromeRAT-StartupPersistence
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium

---

## Hunt Analytics

This hunt detects the execution of PowerShell scripts by suspicious Chrome-named executables that drop files into the Windows Startup folder. This behavior is a hallmark of remote access trojans (RATs) establishing persistence, ensuring their payload runs at every user login. Attackers frequently masquerade their malware as legitimate Chrome executables to evade detection and abuse PowerShell for stealthy file operations. Detected behaviors include:

- PowerShell or pwsh processes launched by executables with Chrome-like names
- Command lines referencing the Windows Startup folder (e.g., `startup`, `start menu\programs\startup`, `appdata\roaming\microsoft\windows\start menu\programs\startup`)

These techniques are associated with RATs attempting to maintain persistence on compromised endpoints.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                               |
|------------------------------|-------------|--------------|-------------------------------------------------------------|
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                                       |
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell               |
| TA0003 - Persistence         | T1547.001   | —            | Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder |

---

## Hunt Query Logic

This query identifies suspicious process launches by looking for:

- PowerShell or pwsh processes
- Parent process (actor) with a Chrome-like name (e.g., `chrome.exe`, `chrome_updater.exe`, `googlechrome.exe`, or any process name containing `chrome`)
- Command lines referencing the Windows Startup folder, indicating an attempt to establish persistence

These patterns are indicative of RATs using masquerading and persistence techniques.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Fake Chrome RAT Dropping File in Startup via PowerShell
// Description: Detects PowerShell execution by suspicious Chrome-named executables that drop files into the Windows Startup folder, a common persistence technique for RATs.
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1059.001
// MITRE ATT&CK TTP ID: T1547.001

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "powershell.exe"
        or action_process_image_name = "pwsh.exe"
    )
    and (
        actor_process_image_name = "chrome.exe"
        or actor_process_image_name = "chrome_updater.exe"
        or actor_process_image_name = "chrome update.exe"
        or actor_process_image_name = "googlechrome.exe"
        or actor_process_image_name contains "chrome"
    )
    and (
        action_process_image_command_line contains "startup"
        or action_process_image_command_line contains "start menu\programs\startup"
        or action_process_image_command_line contains "appdata\roaming\microsoft\windows\start menu\programs\startup"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PowerShell scripts and drop files in the Startup folder.
- **Required Artifacts:** Process creation logs, command-line arguments, and parent process information.

---

## Considerations

- Review the parent process and command line for legitimacy.
- Correlate with user activity and software installation logs to determine if the activity is user-initiated or malicious.
- Investigate any files dropped in the Startup folder for signs of RAT payloads or persistence mechanisms.
- Validate if the parent process is a legitimate Chrome binary or a masqueraded RAT executable.

---

## False Positives

False positives may occur if:

- Legitimate Chrome-based applications or updaters use PowerShell for benign persistence or automation.
- IT staff or users intentionally create scripts for startup automation.

---

## Recommended Response Actions

1. Investigate the parent process and command line for intent and legitimacy.
2. Analyze files dropped in the Startup folder for malicious content.
3. Review user activity and system logs for signs of RAT deployment or persistence.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor suspicious Chrome-named executables and PowerShell persistence attempts.

---

## References

- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [CISA AA25-203A: #StopRansomware: Interlock](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-23 | Initial Detection | Created hunt query to detect Fake Chrome RAT persistence via PowerShell in Startup folder   |
