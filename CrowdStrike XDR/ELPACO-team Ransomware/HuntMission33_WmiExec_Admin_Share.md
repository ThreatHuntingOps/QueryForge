# Correlate wmiexec.exe Use with File Creation in ADMIN$ Share

## Severity or Impact of the Detected Behavior
- **Risk Score:** 96
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-WmiexecAdminShare
- **Operating Systems:** WindowsServer, WindowsEndpoint, DomainController
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with remote command execution and output redirection using `wmiexec.exe`. It identifies when remote commands executed via `wmiexec.exe` (as child processes of `wmiprvse.exe`) result in file creation in the `ADMIN$` share, typically with output redirection files named as epoch timestamps (e.g., `C:\Windows\ADMIN$\<epoch>.txt`).

Detected behaviors include:

- Process creation by `wmiprvse.exe` (e.g., `cmd.exe`, `net1.exe`, `whoami.exe`)
- Subsequent file creation in the `ADMIN$` share with epoch timestamp file names
- Correlation of these events by process context, indicating remote command output redirection and possible data staging

Such activity is a strong indicator of lateral movement, data staging, and remote command execution by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021       | 003          | Remote Services: Windows Remote Management (WMI) |
| TA0009 - Collection          | T1105       | —            | Ingress Tool Transfer                         |
| TA0009 - Collection          | T1005       | —            | Data from Local System                        |

---

## Hunt Query Logic

This query identifies when remote commands executed via `wmiexec.exe` result in file creation in the `ADMIN$` share, a strong indicator of output redirection and data staging.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: process creation by wmiprvse.exe (remote command execution)    
#event_simpleName=ProcessRollup2    
| ParentBaseFileName="wmiprvse.exe"    
| (FileName="cmd.exe" or FileName="net1.exe" or FileName="whoami.exe")    
| join(    
  {    
    // Inner query: file creation in ADMIN$ share (epoch timestamp file)    
    #event_simpleName=FileCreate    
    | FilePath=/C:\Windows\ADMIN\$\[0-9]{10,}\.txt?/i    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[FilePath, FileName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, FilePath]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A              | FileCreate             | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute remote commands via WMI and write files to ADMIN$ share.
- **Required Artifacts:** Process creation logs, file creation logs, process context correlation.

---

## Considerations

- Validate the context of the remote command execution and file creation to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate remote administration or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized tool transfer or data staging is detected.
2. Investigate the source and intent of the remote command execution and file creation.
3. Review all processes associated with the tool and files for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1021.003 – Remote Services: Windows Remote Management (WMI)](https://attack.mitre.org/techniques/T1021/003/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-28 | Initial Detection | Created hunt query to detect wmiexec use and file creation in ADMIN$ share |
