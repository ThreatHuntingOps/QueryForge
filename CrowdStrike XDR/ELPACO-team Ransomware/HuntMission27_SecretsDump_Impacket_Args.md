# Correlate secretsdump.exe Execution with Unique Impacket Arguments

## Severity or Impact of the Detected Behavior
- **Risk Score:** 96
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-SecretsdumpImpacketArgs
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects execution of `secretsdump.exe` (Impacket tool) with unique command line arguments such as `-hashes`, `-just-dc`, or `-outputfile`, which are strong indicators of credential dumping activity. These arguments are commonly used by attackers to extract credentials from remote systems, domain controllers, or to save output for later exfiltration.

Detected behaviors include:

- Execution of `secretsdump.exe` with Impacket-specific arguments (`-hashes`, `-just-dc`, `-outputfile`)
- Correlation of these events by asset and computer name, indicating credential dumping or targeted extraction

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

This query identifies when `secretsdump.exe` is executed with unique Impacket arguments, a strong indicator of credential dumping or targeted extraction.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: secretsdump.exe execution with Impacket arguments    
#event_simpleName=ProcessRollup2    
| FileName="secretsdump.exe"    
| CommandLine=/(-hashes|-just-dc|-outputfile)/i    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, CommandLine]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as secretsdump and provide command line arguments.
- **Required Artifacts:** Process creation logs, command line arguments.

---

## Considerations

- Validate the context of the secretsdump execution and command line arguments to reduce false positives.
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
2. Investigate the source and intent of the secretsdump execution and arguments.
3. Review all processes associated with the tool for further malicious activity.
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
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect secretsdump execution with unique Impacket arguments |
