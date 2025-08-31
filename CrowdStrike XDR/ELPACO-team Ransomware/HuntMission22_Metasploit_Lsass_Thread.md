# Correlate Metasploit Loader with Remote Thread Creation in LSASS

## Severity or Impact of the Detected Behavior
- **Risk Score:** 99
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RemoteThreadLSASS
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with credential dumping or shellcode injection. It identifies when the Metasploit loader (`HAHLGiDDb.exe`) creates a remote thread in the `lsass.exe` process, which is a strong indicator of credential dumping or process injection targeting LSASS memory.

Detected behaviors include:

- Creation of the Metasploit loader process (`HAHLGiDDb.exe`)
- The loader creating a remote thread in the `lsass.exe` process
- Correlation of these events by process context, indicating credential dumping or shellcode injection

Such activity is a strong indicator of credential access and post-exploitation activity by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1055       | 002          | Process Injection: Portable Executable Injection |
| TA0006 - Credential Access   | T1003       | 001          | OS Credential Dumping: LSASS Memory           |

---

## Hunt Query Logic

This query identifies when the Metasploit loader creates a remote thread in the `lsass.exe` process, a strong indicator of credential dumping or shellcode injection.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: Metasploit loader process    
#event_simpleName=ProcessRollup2    
| FileName="HAHLGiDDb.exe"    
| join(    
  {    
    // Inner query: remote thread creation in lsass.exe    
    #event_simpleName=RemoteThreadCreated    
    | TargetProcessName="lsass.exe"    
  }    
  , field=TargetProcessId    
  , key=SourceProcessId    
  , include=[TargetProcessName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, TargetProcessName]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A              | RemoteThreadCreated    | Process             | Remote Thread Creation |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as the Metasploit loader and create remote threads in LSASS.
- **Required Artifacts:** Process creation logs, remote thread creation logs, process context correlation.

---

## Considerations

- Validate the context of the remote thread creation to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately create remote threads in LSASS for diagnostics or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized LSASS access is detected.
2. Investigate the source and intent of the remote thread creation.
3. Review all processes associated with the loader and LSASS for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1055.002 – Process Injection: Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002/)
- [MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect Metasploit loader and remote thread creation in LSASS |
