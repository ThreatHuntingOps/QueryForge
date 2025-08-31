# Correlate secretsdump.exe Execution with Sessionresume File Creation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-SecretsdumpSessionresume
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with credential dumping from remote systems using Impacket's `secretsdump.exe`. It identifies execution of `secretsdump.exe` and the creation of a file starting with `sessionresume_`, which is a strong indicator of credential dumping and session harvesting.

Detected behaviors include:

- Execution of `secretsdump.exe` (Impacket tool)
- Creation of a file with the prefix `sessionresume_` and an 8-character alphanumeric suffix
- Correlation of these events by process context, indicating credential dumping from remote systems

Such activity is a strong indicator of credential access and post-exploitation activity by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0006 - Credential Access   | T1003       | 001          | OS Credential Dumping: LSASS Memory           |
| TA0006 - Credential Access   | T1552       | 002          | Unsecured Credentials: Credentials in Registry |
| TA0006 - Credential Access   | T1555       | 003          | Credentials from Web Browsers                 |

---

## Hunt Query Logic

This query identifies when `secretsdump.exe` is executed and a file with the prefix `sessionresume_` is created, a strong indicator of credential dumping from remote systems.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: secretsdump.exe execution    
#event_simpleName=ProcessRollup2    
| FileName="secretsdump.exe"    
| join(    
  {    
    // Inner query: file creation with sessionresume_ prefix    
    #event_simpleName=FileCreate    
    | FileName=/^sessionresume_[A-Za-z0-9]{8}$/i    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[FileName, FilePath]    
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

- **Required Permissions:** Attacker must be able to execute code as secretsdump and write files.
- **Required Artifacts:** Process creation logs, file creation logs, process context correlation.

---

## Considerations

- Validate the context of the secretsdump execution and file creation to reduce false positives.
- Confirm that the activity is not part of legitimate security testing or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate penetration testing or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized credential dumping is detected.
2. Investigate the source and intent of the secretsdump execution and sessionresume file creation.
3. Review all processes associated with the tool and file for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK: T1552.002 – Unsecured Credentials: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002/)
- [MITRE ATT&CK: T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect secretsdump execution and sessionresume file creation |
