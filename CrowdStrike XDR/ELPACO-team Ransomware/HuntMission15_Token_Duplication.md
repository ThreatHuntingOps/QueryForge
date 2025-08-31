# Correlate Metasploit Loader with Process Access to SYSTEM Processes (Token Duplication)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-TokenDuplication
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Metasploit privilege escalation and credential access. It identifies when the Metasploit loader (`HAHLGiDDb.exe`) attempts to access SYSTEM processes (e.g., `lsass.exe`, `rpcss.exe`) with high privileges (`GrantedAccess=0x1fffff`), indicating a likely attempt to duplicate or steal a privileged token. This pattern is strongly associated with token impersonation, process injection, and credential dumping.

Detected behaviors include:

- Creation of the Metasploit loader process (`HAHLGiDDb.exe`)
- The loader accessing SYSTEM processes (`lsass.exe`, `rpcss.exe`) with high privileges
- Correlation of these events by process context, indicating token duplication or credential theft attempt

Such activity is a strong indicator of privilege escalation, credential access, and post-exploitation activity by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0004 - Privilege Escalation| T1134       | 001          | Access Token Manipulation: Token Impersonation/Theft |
| TA0004 - Privilege Escalation| T1055       | —            | Process Injection                             |
| TA0006 - Credential Access   | T1003       | 001          | OS Credential Dumping: LSASS Memory           |

---

## Hunt Query Logic

This query identifies when the Metasploit loader attempts to access SYSTEM processes with high privileges, indicating a token duplication or credential theft attempt.

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
    // Inner query: process access to SYSTEM processes    
    #event_simpleName=ProcessAccess    
    | TargetProcessName=/lsass\.exe|rpcss\.exe/i    
    | GrantedAccess="0x1fffff"    
    | TargetUserName="NT AUTHORITY\SYSTEM"    
  }    
  , field=TargetProcessId    
  , key=SourceProcessId    
  , include=[TargetProcessName, GrantedAccess, TargetUserName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, TargetProcessName, GrantedAccess, TargetUserName]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A              | ProcessAccess      | Process             | Process Access         |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as the Metasploit loader and access SYSTEM processes with high privileges.
- **Required Artifacts:** Process creation logs, process access logs, process context correlation.

---

## Considerations

- Validate the context of the SYSTEM process access to reduce false positives.
- Confirm that the SYSTEM process access is not part of legitimate administrative or update activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or automated tools legitimately access SYSTEM processes for diagnostics or backup.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the SYSTEM process access.
3. Review all processes associated with the loader and SYSTEM process access for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1134.001 – Access Token Manipulation: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect Metasploit loader and SYSTEM process access for token duplication |
