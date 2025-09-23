# Detection: CORNFLAKE.V3 Initial Access via Windows+R PowerShell and Follow-on Node.js Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-RunDialog-PSH-NodeJS
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics
This hunt set targets the CORNFLAKE.V3 intrusion flow observed by Mandiant. It provides layered detections from initial command execution to process lineage:

- Initial access: PowerShell invoked from Windows+R “Run” dialog, consistent with ClickFix-style lures.
- Staging: PowerShell uses iwr/irm with stealth flags (-w h -c / -windowstyle hidden -command) to pull a time-based path from 138.199.161[.]141:8080.
- Payload staging: Node.js ZIP downloaded and extracted into %APPDATA%, then execution of:
  `%APPDATA%\node-v22.11.0-win-x64\node.exe -e ""`
- Follow-on activity: Reconnaissance and persistence commands launched under the node.exe lineage.

These behaviors collectively indicate initial execution, ingress tool transfer, and staged payload execution with subsequent discovery and persistence.

---

## ATT&CK Mapping

| Tactic                        | Technique | Subtechnique | Technique Name                                   |
|------------------------------|-----------|--------------|--------------------------------------------------|
| TA0002 - Execution           | T1059.001 |              | Command and Scripting Interpreter: PowerShell    |
| TA0002 - Execution           | T1204.002 |              | User Execution: Malicious File                   |
| TA0011 - Command and Control | T1105     |              | Ingress Tool Transfer                            |
| TA0002 - Execution           | T1059.007 |              | Command and Scripting Interpreter: JavaScript    |
| TA0007 - Discovery           | T1057     |              | Process Discovery                                |
| TA0003 - Persistence         | T1547     |              | Boot or Logon Autostart Execution (verify exact subtechnique) |

Note: Discovery and persistence TTPs are expected under node.exe lineage; confirm specific subtechniques during investigation.

---

## Hunt Query Logic
Detects Run-dialog driven PowerShell with hidden window and command flags consistent with ClickFix/RunMRU lures:
- explorer.exe spawning powershell.exe/pwsh.exe with “-w h -c” or “-windowstyle hidden -command”.

This represents the initial access and staging phase prior to Node.js payload deployment.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: PowerShell from Run dialog with hidden window and command (-w h -c)
// Description: Detects PowerShell executions consistent with ClickFix/RunMRU copy-paste lures: explorer spawning powershell.exe with "-w h -c" or "-windowstyle hidden -command" patterns.
// MITRE ATT&CK TTP ID: T1059.001
// MITRE ATT&CK TTP ID: T1204.002
// MITRE ATT&CK TTP ID: T1105

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
and event_sub_type = ENUM.PROCESS_START 
and agent_os_type = ENUM.AGENT_OS_WINDOWS 
and action_process_image_name in ("powershell.exe", "pwsh.exe", "powershell_ise.exe") 
and ( 
  action_process_image_command_line contains "-w h -c" 
  or (action_process_image_command_line contains "-windowstyle" 
      and action_process_image_command_line contains "hidden" 
      and action_process_image_command_line contains "-command") 
) 
and actor_process_image_name = "explorer.exe" 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, 
action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, 
causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, 
event_id, agent_id, _product 
| sort desc _time
```

---

## Additional Follow-on Hunts (Recommended)

1) PowerShell staging from 138.199.161[.]141:8080 with iwr/irm
- Filter `action_process_image_name` in ("powershell.exe","pwsh.exe") and `action_process_image_command_line` contains any of ("iwr","irm") and contains `138.199.161.141:8080` or `138.199.161[.]141:8080`.
- Heuristics: presence of `-UseBasicParsing`, `-windowstyle hidden`, `-enc`/`-e`, time-based path fragments.

2) Node.js payload staging in %APPDATA%
- File events: ZIP written under `%APPDATA%` and extracted path `%APPDATA%\node-v22.11.0-win-x64\`.
- Process events: `action_process_image_name = "node.exe"` and path endswith `\node-v22.11.0-win-x64\node.exe` and command line contains `-e`.

3) Recon/persistence under node.exe lineage
- Processes where actor/causality lineage includes node.exe from `%APPDATA%\node-v22.11.0-win-x64\`.
- Look for registry edits, scheduled tasks, WMI, or LOLBins (e.g., schtasks.exe, reg.exe, net.exe, whoami.exe, ipconfig.exe).

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user sufficient for Run dialog execution and %APPDATA% write; elevated rights may be used for persistence.
- **Required Artifacts:** Process creation logs with full command line, file creation/modification in %APPDATA%, network connections to `138.199.161[.]141:8080`, registry/scheduled task events.

---

## Considerations
- ClickFix/RunMRU lures are user-driven; correlate with foreground user session and clipboard history if available.
- Run-dialog sourced PowerShell is uncommon in enterprise baselines. Validate against IT scripts or administrative workflows to reduce FPs.
- IP `138.199.161[.]141:8080` and time-based pathing are strong signals; treat as high fidelity when combined with hidden window flags.
- Node.js under `%APPDATA%\node-v22.11.0-win-x64\` is atypical. Legitimate developer installs often reside under Program Files and are not invoked with `-e` inline code.

---

## False Positives
- Rare: Power users pasting legitimate one-liners into Run dialog for quick tasks.
- Some IT automation may use hidden window flags; however, explorer.exe parent from Run dialog is a key discriminator.
- Developer machines might have node.exe, but location and invocation (`-e`) and lineage from PowerShell staging should minimize benign matches.

---

## Recommended Response Actions
1) Triage initial event:
   - Review `actor_effective_username`, explorer.exe -> powershell.exe lineage, and full command line.
2) Scope staging and payload:
   - Hunt for connections to `138.199.161[.]141:8080`, iwr/irm usage, and ZIP artifacts in `%APPDATA%`.
3) Contain and eradicate:
   - Isolate affected endpoints.
   - Quarantine `%APPDATA%\node-v22.11.0-win-x64\` and related artifacts; block node.exe execution from user profiles.
4) Persistence and recon sweep:
   - Search for scheduled tasks, Run/RunOnce keys, WMI event consumers under the node.exe lineage.
5) Block and monitor:
   - Add network blocks for the noted IP/port.
   - Add EDR rules for Run-dialog PowerShell with hidden window flags and for `node.exe -e` from user profile.

---

## References
- MITRE ATT&CK: T1059.001 - PowerShell https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK: T1204.002 - User Execution: Malicious File https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK: T1105 - Ingress Tool Transfer https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK: T1059 - Command and Scripting Interpreter https://attack.mitre.org/techniques/T1059/

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection | CORNFLAKE.V3 Run-dialog PSH, staging via 138.199.161[.]141:8080, Node.js payload |
