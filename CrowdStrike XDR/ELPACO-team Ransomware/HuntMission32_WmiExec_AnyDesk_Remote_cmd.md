# Correlate wmiexec.exe Drop via AnyDesk with Remote Command Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-WmiexecAnyDeskRemoteCmd
- **Operating Systems:** WindowsServer, WindowsEndpoint, DomainController
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with remote command execution and lateral movement using `wmiexec.exe` dropped via AnyDesk. It identifies when `wmiexec.exe` is dropped (typically via explorer.exe, indicating AnyDesk copy/paste or file transfer), then used to spawn remote commands as child processes of `wmiprvse.exe` on a domain controller.

Detected behaviors include:

- Creation of `wmiexec.exe` via file transfer (AnyDesk, explorer.exe)
- Subsequent process creation by `wmiprvse.exe` (e.g., `cmd.exe`, `net1.exe`, `whoami.exe`)
- Correlation of these events by process context, indicating remote command execution and possible lateral movement

Such activity is a strong indicator of ingress tool transfer, remote command execution, and credential access by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021       | 003          | Remote Services: Windows Remote Management (WMI) |
| TA0006 - Credential Access   | T1075       | —            | Pass the Hash                                 |
| TA0009 - Collection          | T1105       | —            | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies when `wmiexec.exe` is dropped via AnyDesk and then used to spawn remote commands as child processes of `wmiprvse.exe`, a strong indicator of lateral movement and remote command execution.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: wmiexec.exe file creation via explorer.exe (AnyDesk copy/paste)    
#event_simpleName=FileCreate    
| FileName="wmiexec.exe"    
| join(    
  {    
    // Inner query: process creation by wmiprvse.exe (remote command execution)    
    #event_simpleName=ProcessRollup2    
    | ParentBaseFileName="wmiprvse.exe"    
    | (FileName="cmd.exe" or FileName="net1.exe" or FileName="whoami.exe")    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[ParentBaseFileName, FileName, CommandLine]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, ParentBaseFileName, CommandLine]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | FileCreate             | File                | File Creation          |
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to transfer files via AnyDesk and execute remote commands via WMI.
- **Required Artifacts:** File creation logs, process creation logs, process context correlation.

---

## Considerations

- Validate the context of the file transfer and remote command execution to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate remote administration or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized tool transfer or remote command execution is detected.
2. Investigate the source and intent of the file transfer and remote command execution.
3. Review all processes associated with the tool and remote commands for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1021.003 – Remote Services: Windows Remote Management (WMI)](https://attack.mitre.org/techniques/T1021/003/)
- [MITRE ATT&CK: T1075 – Pass the Hash](https://attack.mitre.org/techniques/T1075/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-28 | Initial Detection | Created hunt query to detect wmiexec drop via AnyDesk and remote command execution |
