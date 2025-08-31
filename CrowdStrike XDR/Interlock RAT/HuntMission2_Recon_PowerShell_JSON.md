# Detection of Reconnaissance PowerShell Commands Outputting JSON

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** Medium-High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Recon-PowerShell-JSON
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects PowerShell processes executing common system and network reconnaissance commands, with results output as JSON. Attackers and malware frequently use this pattern to automate host and network profiling, making it easier to exfiltrate or process the data. The use of `ConvertTo-Json` in conjunction with reconnaissance commands is a strong indicator of automated or scripted discovery activity.

Detected behaviors include:

- PowerShell execution of commands such as `Get-NetNeighbor`, `systeminfo`, `tasklist`, `Get-Service`, or `Get-PSDrive`
- Output of command results using `ConvertTo-Json`
- Automated system and network profiling, often preceding lateral movement or exfiltration

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery           | T1082       | —            | System Information Discovery                  |
| TA0007 - Discovery           | T1057       | —            | Process Discovery                            |
| TA0007 - Discovery           | T1007       | —            | System Service Discovery                     |
| TA0007 - Discovery           | T1016       | —            | System Network Configuration Discovery        |
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell |

---

## Hunt Query Logic

This query identifies PowerShell processes that execute common reconnaissance commands and output the results as JSON. This behavior is often associated with automated profiling by malware or threat actors.

Key detection logic:

- `powershell.exe` process execution
- Command line includes one or more of: `get-netneighbor`, `systeminfo`, `tasklist`, `get-service`, `get-psdrive`
- Command line also includes `convertto-json`
- Windows endpoint context

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Detection of Reconnaissance PowerShell Commands Outputting JSON
// Description: Detects PowerShell processes executing common system and network reconnaissance commands, outputting results as JSON. This is often used by malware for automated profiling and exfiltration.
// MITRE ATT&CK TTPs: T1082, T1057, T1007, T1016, T1059.001

#event_simpleName=ProcessRollup2 
| FileName = "powershell.exe" 
| ( 
    CommandLine = "*Get-NetNeighbor*" OR 
    CommandLine = "*systeminfo*" OR 
    CommandLine = "*tasklist*" OR 
    CommandLine = "*Get-Service*" OR 
    CommandLine = "*Get-PSDrive*" 
  ) 
| CommandLine = "*ConvertTo-Json*" 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PowerShell.
- **Required Artifacts:** Process creation logs, command-line arguments.

---

## Considerations

- Review the context of the PowerShell process and command line for legitimacy.
- Correlate with user activity, scheduled tasks, or automation frameworks to determine if the activity is benign or malicious.
- Investigate any subsequent network connections or file writes that may indicate exfiltration of the JSON output.

---

## False Positives

False positives may occur if:

- System administrators or automation tools use PowerShell to collect system/network information and output as JSON for legitimate purposes.
- Security tools or monitoring scripts perform similar actions.

---

## Recommended Response Actions

1. Investigate the process tree and command line for intent and legitimacy.
2. Review user activity and system logs for signs of automated or suspicious behavior.
3. Analyze any files or network connections associated with the PowerShell process.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor suspicious PowerShell usage patterns.

---

## References

- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK: T1057 – Process Discovery](https://attack.mitre.org/techniques/T1057/)
- [MITRE ATT&CK: T1007 – System Service Discovery](https://attack.mitre.org/techniques/T1007/)
- [MITRE ATT&CK: T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-17 | Initial Detection | Created hunt query to detect reconnaissance PowerShell commands outputting JSON             |
