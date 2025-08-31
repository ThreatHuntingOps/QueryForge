# Detection of Interlock RAT Execution via PowerShell Spawning Suspicious PHP with Non-Standard Config

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-InterlockRAT-PowerShell-PHP
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a highly suspicious process chain indicative of Interlock RAT execution. Specifically, it identifies instances where `powershell.exe` spawns `php.exe` from the user's `AppData\Roaming\php` directory, with command-line arguments enabling the ZIP extension and referencing a `.cfg` file. This pattern matches the known Interlock RAT execution chain, where PowerShell is used to launch PHP with a non-standard configuration file, often as part of a post-exploitation or initial access campaign.

Detected behaviors include:

- PowerShell spawning PHP from a non-standard user directory
- PHP invoked with the ZIP extension enabled and a `.cfg` file as an argument
- Process lineage and command-line arguments matching Interlock RAT TTPs

These techniques are associated with remote access trojans, post-exploitation frameworks, and targeted attacks leveraging masquerading and user execution.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                |
| TA0005 - Defense Evasion     | T1036.005   | —            | Masquerading: Match Legitimate Name or Location |
| TA0001 - Initial Access      | T1566.001   | —            | Phishing: Spearphishing Attachment            |

---

## Hunt Query Logic

This query identifies suspicious PHP executions from the user's AppData\Roaming directory, specifically when the parent process is PowerShell. It looks for PHP invoked with ZIP extension enabled and a `.cfg` file as an argument, which matches the Interlock RAT execution chain.

Key detection logic:

- `php.exe` executed from `appdata\roaming\php\php.exe`
- Command line includes `-d extension=zip` and references a `.cfg` file
- Parent process is `powershell.exe`
- Windows endpoint context

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Detection of Interlock RAT Execution via PowerShell Spawning Suspicious PHP with Non-Standard Config
// Description: Detects PowerShell spawning php.exe from AppData\Roaming with ZIP extension enabled and a .cfg file, matching Interlock RAT TTPs.
// MITRE ATT&CK TTPs: T1059.001, T1059.003, T1204.002, T1036.005, T1566.001

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "php.exe" 
    and action_process_image_path contains "appdata\roaming\php\php.exe" 
    and action_process_image_command_line contains "-d extension=zip" 
    and action_process_image_command_line contains ".cfg" 
    and actor_process_image_name = "powershell.exe" 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, event_id, agent_id, _product 
| sort desc _time  
```

---

## Data Sources

| Log Provider   | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|----------------|------------------|---------------------|------------------------|
| Cortex XSIAM   | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PowerShell and PHP binaries.
- **Required Artifacts:** Process creation logs, command-line arguments, and parent-child process relationships.

---

## Considerations

- Review the source and context of the PowerShell and PHP processes for legitimacy.
- Correlate with user activity, email, or download logs to determine if the activity is user-initiated or automated.
- Investigate any network connections or file writes associated with the detected PHP process.
- Validate if the `.cfg` file or PHP binary is associated with known Interlock RAT samples or threat intelligence indicators.

---

## False Positives

False positives are unlikely but may occur if:

- Legitimate automation or development tools use PHP in this manner (rare in enterprise environments).
- Security testing or red team activity mimics this execution chain.

---

## Recommended Response Actions

1. Investigate the process tree and command line for intent and legitimacy.
2. Analyze any files or network connections created by the PHP process.
3. Review user activity and system logs for signs of compromise or lateral movement.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor execution of PHP from user AppData directories.

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [Interlock RAT Analysis – ANY.RUN](https://any.run/malware-trends/interlock)
- [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-16 | Initial Detection | Created hunt query to detect Interlock RAT execution via PowerShell spawning PHP with non-standard config |
