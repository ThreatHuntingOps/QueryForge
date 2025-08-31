# Detection of WSF Script Execution via CScript

## Severity or Impact of the Detected Behavior
- **Risk Score:** 70
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-WSFScript-CScript
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of `.wsf` (Windows Script File) scripts using `cscript.exe`, particularly those launched from the `%temp%` directory and with stealthy flags such as `//nologo`. Attackers often leverage `.wsf` scripts for initial access, payload delivery, or execution of malicious code, as these scripts can combine multiple scripting languages and evade basic detection. The use of `%temp%` and stealth flags is a common technique to avoid user suspicion and security controls.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1059.005   | —            | Command and Scripting Interpreter: Visual Basic        |
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                        |

---

## Hunt Query Logic

This query identifies suspicious executions of `cscript.exe` that match the following indicators:

- The process name is `cscript.exe` (case-insensitive)
- The command line includes execution of a `.wsf` file from the `%temp%` directory
- The command line includes the `//nologo` flag, which suppresses banner output for stealth

Such patterns are often associated with malware delivery, initial access, or execution of scripts dropped by other malicious processes.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
// Title: Suspicious cscript.exe Execution of .wsf from Temp with //nologo
// Description: Detects suspicious executions of cscript.exe where a .wsf file is run from the %temp% directory with the //nologo flag, a pattern often associated with malware delivery or script-based attacks.
// MITRE ATT&CK TTP ID: T1059.005
// MITRE ATT&CK TTP ID: T1204.002

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name = "cscript.exe"
    and action_process_image_command_line contains "\temp\"
    and action_process_image_command_line contains ".wsf"
    and action_process_image_command_line contains "//nologo"
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute scripts via `cscript.exe`.
- **Required Artifacts:** Script files in `%temp%`, process creation logs, command-line arguments.

---

## Considerations

- Investigate the `.wsf` file's contents and origin for malicious code.
- Review the parent process to determine how the script was dropped or executed.
- Correlate with other endpoint activity for signs of lateral movement or persistence.
- Check for additional files or payloads dropped in `%temp%`.

---

## False Positives

False positives may occur if:

- Legitimate administrative or automation scripts are run from `%temp%` using `cscript.exe`.
- Software installers or updaters temporarily use `.wsf` scripts for setup tasks.

---

## Recommended Response Actions

1. Investigate the `.wsf` script and its source.
2. Analyze command-line arguments for suspicious or obfuscated code.
3. Review parent and child process relationships for further malicious activity.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized scripts or payloads from `%temp%`.

---

## References

- [MITRE ATT&CK: T1059.005 – Command and Scripting Interpreter: Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [Microsoft: Windows Script Files (WSF)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc749603(v=ws.10))

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-01 | Initial Detection | Created hunt query to detect suspicious WSF script execution via cscript.exe                |
