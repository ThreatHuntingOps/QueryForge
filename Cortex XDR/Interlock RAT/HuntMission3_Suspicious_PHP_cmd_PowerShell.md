# Detection of Suspicious PHP Spawning cmd.exe and PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-InterlockRAT-PHP-cmd-PowerShell
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a highly suspicious process ancestry indicative of Interlock RAT or similar post-exploitation frameworks. It identifies cases where a `php.exe` process, running from a user's `AppData\Roaming\php` directory, spawns `cmd.exe`, which in turn spawns `powershell.exe`. This process chain is rarely seen in legitimate activity and is strongly associated with malware execution, privilege escalation, or lateral movement.

Detected behaviors include:

- PHP executed from a non-standard user directory
- PHP spawning `cmd.exe`, which then spawns `powershell.exe`
- Process ancestry matching known Interlock RAT TTPs

These techniques are associated with remote access trojans, defense evasion, and masquerading.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell |
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                |
| TA0005 - Defense Evasion     | T1036.005   | —            | Masquerading: Match Legitimate Name or Location |

---

## Hunt Query Logic

This query identifies suspicious process ancestry where:

- `php.exe` is executed from `appdata\roaming\php\php.exe`
- `php.exe` spawns `cmd.exe`
- `cmd.exe` spawns `powershell.exe`
- Windows endpoint context

This ancestry is highly suspicious and matches the Interlock RAT execution chain.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Detection of Suspicious PHP Spawning cmd.exe and PowerShell
// Description: Detects PHP executables running from a user’s AppData\Roaming directory that spawn cmd.exe, which in turn spawns powershell.exe. This ancestry is highly suspicious and matches the Interlock RAT execution chain.
// MITRE ATT&CK TTPs: T1059.001, T1204.002, T1036.005

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "powershell.exe" 
    and actor_process_image_name = "cmd.exe" 
    and causality_actor_process_image_name = "php.exe" 
    and causality_actor_process_image_path contains "appdata\roaming\php\php.exe" 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, causality_actor_process_image_name, causality_actor_process_image_path, event_id, agent_id, _product 
| sort desc _time 
```

---

## Data Sources

| Log Provider   | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|----------------|------------------|---------------------|------------------------|
| Cortex XSIAM   | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PHP, cmd.exe, and PowerShell.
- **Required Artifacts:** Process creation logs, command-line arguments, and process ancestry.

---

## Considerations

- Review the full process tree for legitimacy and context.
- Correlate with user activity, scheduled tasks, or automation frameworks to determine if the activity is benign or malicious.
- Investigate any files or network connections created by the PHP, cmd.exe, or PowerShell processes.
- Validate if the PHP binary or its parent files are associated with known Interlock RAT samples or threat intelligence indicators.

---

## False Positives

False positives are unlikely but may occur if:

- Legitimate automation or development tools use this process chain (rare in enterprise environments).
- Security testing or red team activity mimics this execution chain.

---

## Recommended Response Actions

1. Investigate the process tree and command line for intent and legitimacy.
2. Analyze any files or network connections created by the involved processes.
3. Review user activity and system logs for signs of compromise or lateral movement.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor execution of PHP from user AppData directories.

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [Interlock RAT Analysis – ANY.RUN](https://any.run/malware-trends/interlock)
- [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-16 | Initial Detection | Created hunt query to detect suspicious PHP spawning cmd.exe and PowerShell                 |
