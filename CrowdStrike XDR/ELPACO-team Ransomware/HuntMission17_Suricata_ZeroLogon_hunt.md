# Correlate Suricata Alert with Zerologon Exploit Attempt

## Severity or Impact of the Detected Behavior
- **Risk Score:** 99
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-SuricataZerologon
- **Operating Systems:** WindowsServer, DomainController
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Zerologon exploitation attempts. It identifies Suricata alerts for Zerologon exploitation (e.g., signatures for Zerologon, CVE-2020-1472, or Netlogon) and correlates these with execution of `zero.exe` on the same host. This pattern is strongly associated with exploitation for privilege escalation and post-exploitation activity.

Detected behaviors include:

- Suricata alert for Zerologon exploitation attempt (e.g., `Zerologon`, `CVE-2020-1472`, `Netlogon`)
- Execution of `zero.exe` on the same host
- Correlation of these events by asset ID, indicating exploitation attempt and tool execution

Such activity is a strong indicator of Zerologon exploitation and post-exploitation activity by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0004 - Privilege Escalation| T1068       | —            | Exploitation for Privilege Escalation         |
| TA0006 - Credential Access   | T1078       | —            | Valid Accounts                                |

---

## Hunt Query Logic

This query identifies Suricata alerts for Zerologon exploitation attempts and correlates them with execution of `zero.exe` on the same host. This sequence is a strong indicator of exploitation and post-exploitation activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: Suricata alert for Zerologon    
#event_simpleName=SuricataAlert    
| AlertSignature=/Zerologon|CVE-2020-1472|Netlogon/i    
| join(    
  {    
    // Inner query: zero.exe execution    
    #event_simpleName=ProcessRollup2    
    | FileName="zero.exe"    
  }    
  , field=aid    
  , key=aid    
  , include=[FileName, CommandLine]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([AlertSignature, FileName, CommandLine]))   
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | SuricataAlert      | Network Detection   | IDS Alert              |
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as the exploit tool and trigger network detection.
- **Required Artifacts:** Suricata alert logs, process creation logs, asset correlation.

---

## Considerations

- Validate the context of the Suricata alert and zero.exe execution to reduce false positives.
- Confirm that the activity is not part of legitimate security testing or administrative activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate penetration testing or red team exercises.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected domain controller or server from the network.
2. Investigate the source and intent of the Suricata alert and zero.exe execution.
3. Review all processes associated with the exploit and alert for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable domain controllers and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK: T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect Suricata alert and Zerologon exploit tool execution |
