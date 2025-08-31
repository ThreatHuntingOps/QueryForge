# Correlate AnyDesk Execution with Unattended Access Password Setup

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnyDeskUnattendedAccess
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with the setup of persistent remote access via AnyDesk. It identifies the execution of `AnyDesk.exe` with command-line arguments to start the service or set the unattended access password, and correlates this with a `cmd.exe` process echoing a password (e.g., `P@ssword1`). This pattern is strongly associated with attackers establishing unattended access for persistent remote control following exploitation.

Detected behaviors include:

- Execution of `AnyDesk.exe` with command-line arguments such as `--start-service`, `--set-password`, or `--get-id`
- Correlated `cmd.exe` process echoing a password (e.g., `P@ssword1`)
- Correlation of these events by process context, indicating automated setup of unattended access

Such activity is a strong indicator of attacker persistence and remote access setup following exploitation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence         | T1133       | —            | External Remote Services                      |
| TA0004 - Privilege Escalation| T1547       | 001          | Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies the execution of `AnyDesk.exe` with arguments to start the service or set the unattended access password, and correlates this with a `cmd.exe` process echoing a password. This sequence is a strong indicator of persistent remote access setup.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: AnyDesk execution with service start or password setup    
#event_simpleName=ProcessRollup2    
| FileName="AnyDesk.exe"    
| (CommandLine=/--start-service/i or CommandLine=/--set-password/i or CommandLine=/--get-id/i)    
| join(    
  {    
    // Inner query: echo command to set password    
    #event_simpleName=ProcessRollup2    
    | FileName="cmd.exe"    
    | CommandLine=/echo\s+P@ssword1/i    
  }    
  , field=TargetProcessId // AnyDesk.exe's TargetProcessId    
  , key=ContextProcessId  // cmd.exe's ContextProcessId    
  , include=[CommandLine]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, CommandLine])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and set unattended access passwords via command line.
- **Required Artifacts:** Process creation logs, command-line arguments, process context correlation.

---

## Considerations

- Validate the context of the AnyDesk execution and password setup to reduce false positives.
- Confirm that the unattended access setup is not part of legitimate administrative or support activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately configure AnyDesk for unattended access.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious AnyDesk execution and password setup.
3. Review all processes associated with AnyDesk and cmd.exe for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1133 – External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect AnyDesk execution and unattended access password setup |
