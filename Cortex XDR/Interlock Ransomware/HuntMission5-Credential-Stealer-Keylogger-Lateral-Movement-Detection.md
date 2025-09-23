# Detection of Credential Stealer, Keylogger, and Lateral Movement Tools

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-CredStealer-Keylogger-LateralMove
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects PowerShell commands used to download and execute credential stealers (e.g., `cht.exe`), keylogger DLLs (e.g., `klg.dll`), and information stealers (e.g., Lumma Stealer, Berserk Stealer). It also detects the creation of suspicious files (e.g., `conhost.txt`), and the use of lateral movement tools such as RDP, AnyDesk, and PuTTY. These activities are associated with credential access, privilege escalation, and lateral movement by threat actors. Detected behaviors include:

- PowerShell or pwsh processes downloading or executing credential stealers, keyloggers, or info stealers
- Execution of credential stealer, keylogger, or info stealer binaries
- Creation of suspicious files (e.g., `conhost.txt`)
- Use of lateral movement tools (e.g., AnyDesk)

These techniques are commonly used in multi-stage attacks involving credential theft, persistence, and lateral movement.

---

## ATT&CK Mapping

| Tactic                    | Technique     | Subtechnique | Technique Name                                         |
|--------------------------|---------------|--------------|-------------------------------------------------------|
| TA0006 - Credential Access| T1056.001     | —            | Input Capture: Keylogging                             |
| TA0006 - Credential Access| T1555.003     | —            | Credentials from Web Browsers                         |
| TA0005 - Defense Evasion | T1036.005     | —            | Masquerading: Match Legitimate Name or Location       |
| TA0011 - Command and Control | T1105      | —            | Ingress Tool Transfer                                 |
| TA0008 - Lateral Movement| T1021.001     | —            | Remote Services: Remote Desktop Protocol              |
| TA0008 - Lateral Movement| T1219         | —            | Remote Access Software                                |
| TA0004 - Privilege Escalation| T1078      | —            | Valid Accounts                                        |
| TA0004 - Privilege Escalation| T1078.002  | —            | Domain Accounts                                       |
| TA0006 - Credential Access| T1558.003     | —            | Steal or Forge Kerberos Tickets                       |

---

## Hunt Query Logic

This query identifies suspicious process launches by looking for:

- PowerShell or pwsh processes with command lines referencing credential stealer/keylogger binaries (`cht.exe`, `klg.dll`, `lummastealer`, `berserk`, `iwr`)
- Execution of credential stealer, keylogger, or info stealer binaries (`cht.exe`, `lummastealer.exe`, `berserk.exe`, `klg.dll`)
- Creation of suspicious files (e.g., `conhost.txt`)
- Use of lateral movement tools (e.g., `anydesk.exe`)

These patterns are indicative of credential theft, keylogging, and lateral movement activity.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Credential Stealer, Keylogger, and Lateral Movement Tools Detection
// Description: Detects PowerShell commands downloading/executing credential stealers (cht.exe), keylogger DLLs (klg.dll), suspicious file creation (conhost.txt), and use of lateral movement tools (RDP, AnyDesk, PuTTY, info stealers).
// MITRE ATT&CK TTP ID: TA0006
// MITRE ATT&CK TTP ID: T1056.001
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1555.003
// MITRE ATT&CK TTP ID: T1036.005
// MITRE ATT&CK TTP ID: T1078
// MITRE ATT&CK TTP ID: T1021.001
// MITRE ATT&CK TTP ID: T1219
// MITRE ATT&CK TTP ID: T1558.003
// MITRE ATT&CK TTP ID: T1078.002

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        // PowerShell downloading or executing credential stealer/keylogger
        (
            (action_process_image_name = "powershell.exe" or action_process_image_name = "pwsh.exe")
            and (
                action_process_image_command_line contains "cht.exe"
                or action_process_image_command_line contains "klg.dll"
                or action_process_image_command_line contains "lummastealer"
                or action_process_image_command_line contains "berserk"
                or action_process_image_command_line contains "iwr"
            )
        )
        // Execution of credential stealer/keylogger/info stealer
        or (
            action_process_image_name = "cht.exe"
            or action_process_image_name = "lummastealer.exe"
            or action_process_image_name = "berserk.exe"
            or action_process_image_name = "klg.dll"
        )
        // Creation of suspicious file (conhost.txt)
        or (
            action_process_image_command_line contains "conhost.txt"
        )
        // Use of lateral movement tools
        or (
            action_process_image_name = "anydesk.exe"
        )
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

- **Required Permissions:** User or attacker must be able to execute PowerShell scripts, download or run binaries, and create files.
- **Required Artifacts:** Process creation logs, command-line arguments, and file creation records.

---

## Considerations

- Review the command line, process, and file creation for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or malicious.
- Investigate any binaries or DLLs referenced in the command line for signs of credential theft or keylogging.
- Validate if the use of remote access tools is authorized or part of a threat actor's lateral movement.

---

## False Positives

False positives may occur if:

- IT staff or legitimate automation scripts use similar tools or file names for benign purposes.
- Security tools or monitoring agents execute similar commands for testing or monitoring.

---

## Recommended Response Actions

1. Investigate the command line, process, and file creation for intent and legitimacy.
2. Analyze referenced binaries, DLLs, and files for malicious content.
3. Review user activity and system logs for signs of credential theft, keylogging, or lateral movement.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor suspicious binaries, DLLs, and remote access tool usage.

---

## References

- [MITRE ATT&CK: T1056.001 – Input Capture: Keylogging](https://attack.mitre.org/techniques/T1056/001/)
- [MITRE ATT&CK: T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK: T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK: T1078.002 – Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [MITRE ATT&CK: T1558.003 – Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/003/)
- [CISA AA25-203A: #StopRansomware: Interlock](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-23 | Initial Detection | Created hunt query to detect credential stealer, keylogger, and lateral movement tools      |
