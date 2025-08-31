# Detection of Network Scanning Tools (Advanced IP Scanner, NetScan)

## Severity or Impact of the Detected Behavior

- **Risk Score:** 80  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-NetworkScanner-ToolExec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of third-party network scanning tools, specifically Advanced IP Scanner and SoftPerfect NetScan. These tools are frequently used by attackers to enumerate hosts and services within a network after gaining initial access. The presence of these binaries in process creation logs is a strong indicator of post-exploitation activity, lateral movement preparation, or internal reconnaissance.

Detected behaviors include:

- Execution of `advanced_ip_scanner*.exe` or `netscan*.exe`
- Attempts to enumerate network hosts, open ports, and available services
- Commonly observed in ransomware, red team, and advanced persistent threat (APT) operations

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery            | T1046       | —            | Network Service Discovery                     |

---

## Hunt Query Logic

This query identifies suspicious executions of network scanning tools by matching process creation events for `advanced_ip_scanner*.exe` or `netscan*.exe`. Such activity is rarely seen in legitimate environments and should be investigated, especially if observed outside of authorized IT or security operations.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    

| (FileName = /advanced_ip_scanner.*\.exe/i OR FileName = /netscan.*\.exe/i) 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to execute binaries.
- **Required Artifacts:** Process creation logs, binary hashes, command-line arguments.

---

## Considerations

- Investigate the user account and host context for the detected tool execution.
- Review for additional signs of compromise, such as lateral movement or privilege escalation.
- Correlate with other suspicious events, such as credential dumping or file transfers.
- Check for legitimate IT or security team activity that may explain the execution.

---

## False Positives

False positives may occur if:

- IT or security teams are running network scanning tools for authorized inventory or troubleshooting.
- Automated asset discovery or vulnerability management tools deploy these binaries as part of their operation.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the tool execution.
2. Review recent activity for signs of network enumeration or lateral movement.
3. Check for additional indicators of compromise or privilege escalation.
4. Isolate affected systems if malicious activity is confirmed.
5. Review and restrict access to network scanning tools as needed.

---

## References

- [MITRE ATT&CK: T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-09 | Initial Detection | Created hunt query to detect Advanced IP Scanner and NetScan execution                     |
