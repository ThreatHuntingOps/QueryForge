# Correlate Metasploit Loader with Full-Access Process Handle Acquisition

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-ProcessAccessPreInjection
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Metasploit pre-injection activity. It identifies when the Metasploit loader (`HAHLGiDDb.exe` or similar) accesses other processes (e.g., `svchost.exe`, `tomcat9.exe`, `conhost.exe`, `mysqld.exe`, `java.exe`) with full access rights (`0x1f3fff`), which is a common precursor to process injection and defense evasion.

Detected behaviors include:

- Creation of the Metasploit loader process (`HAHLGiDDb.exe`)
- The loader accessing key processes with full access rights
- Correlation of these events by process context, indicating pre-injection reconnaissance or setup

Such activity is a strong indicator of process injection attempts and possible defense evasion by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                             |
| TA0005 - Defense Evasion     | T1562       | 001          | Impair Defenses: Disable or Modify Tools      |

---

## Hunt Query Logic

This query identifies when the Metasploit loader accesses other processes with full access, a common precursor to process injection and defense evasion.

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
    // Inner query: process access to key processes with full access    
    #event_simpleName=ProcessAccess    
    | TargetProcessName=/svchost\.exe|tomcat9\.exe|conhost\.exe|mysqld\.exe|java\.exe/i    
    | GrantedAccess="0x1f3fff"    
  }    
  , field=TargetProcessId    
  , key=SourceProcessId    
  , include=[TargetProcessName, GrantedAccess]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, TargetProcessName, GrantedAccess]))   
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A              | ProcessAccess      | Process             | Process Access         |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as the Metasploit loader and access other processes with full rights.
- **Required Artifacts:** Process creation logs, process access logs, process context correlation.

---

## Considerations

- Validate the context of the process access to reduce false positives.
- Confirm that the process access is not part of legitimate administrative or update activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or automated tools legitimately access processes with full rights for diagnostics or backup.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the process access.
3. Review all processes associated with the loader and accessed processes for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect Metasploit loader and full-access process handle acquisition |
