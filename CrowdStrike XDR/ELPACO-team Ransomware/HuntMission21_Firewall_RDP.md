# Correlate Firewall Rule Modification for RDP Access

## Severity or Impact of the Detected Behavior
- **Risk Score:** 92
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-FirewallRDP
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of `netsh.exe` with `advfirewall` commands to enable RDP and add inbound rules for TCP port 3389. Attackers often use these commands to ensure RDP is accessible for lateral movement or persistent remote access after initial compromise.

Detected behaviors include:

- Execution of `netsh.exe` with command-line arguments to enable the "Remote Desktop" rule group or add a rule allowing inbound TCP 3389.
- These actions are strong indicators of attempts to enable RDP access, often as part of post-exploitation activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1562       | 004          | Impair Defenses: Disable or Modify System Firewall |
| TA0008 - Lateral Movement    | T1021       | 001          | Remote Services: Remote Desktop Protocol      |

---

## Hunt Query Logic

This query identifies execution of `netsh.exe` with `advfirewall` commands to enable RDP or add inbound rules for TCP port 3389. This is a strong indicator of attempts to enable RDP access for lateral movement or persistence.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: process execution of netsh advfirewall for RDP    
#event_simpleName=ProcessRollup2    
| FileName="netsh.exe"    
| CommandLine=/advfirewall.*(set rule group="remote desktop" new enable=yes|add rule name="allow RDP" dir=in protocol=TCP localport=3389 action=allow)/i    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, CommandLine]))
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and modify firewall rules.
- **Required Artifacts:** Process creation logs, command-line arguments.

---

## Considerations

- Validate the context of the firewall modification to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately enable RDP for remote support or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized RDP enablement is detected.
2. Investigate the source and intent of the firewall modification.
3. Review all processes associated with the firewall changes for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Revert unauthorized firewall changes and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1562.004 – Impair Defenses: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/)
- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect firewall rule modification for RDP access                     |
