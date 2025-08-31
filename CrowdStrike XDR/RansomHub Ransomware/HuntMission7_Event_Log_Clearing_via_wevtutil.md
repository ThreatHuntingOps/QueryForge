# Detection of Windows Event Log Clearing Using wevtutil.exe

## Severity or Impact of the Detected Behavior

- **Risk Score:** 85  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-wevtutil-LogClearing
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of `wevtutil.exe` to clear Windows event logs, a classic anti-forensics and defense evasion technique. Attackers often clear event logs to remove evidence of their activity, making incident response and forensic analysis more difficult. The query focuses on command-line arguments that invoke the clearing (`cl`) of the Security, System, or Application logs, which are critical for tracking system and user activity.

Detected behaviors include:

- Use of `wevtutil.exe` with the `cl` (clear log) command targeting Security, System, or Application logs
- Attempts to erase evidence of compromise or malicious activity
- Commonly observed in ransomware, privilege escalation, and post-exploitation scenarios

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion      | T1070.001   | —            | Indicator Removal on Host: Clear Windows Event Logs |

---

## Hunt Query Logic

This query identifies suspicious executions of `wevtutil.exe` with command-line arguments that clear the Security, System, or Application event logs. Such patterns are often seen in attacks where adversaries attempt to cover their tracks.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    

| (FileName = "wevtutil.exe")    

| (CommandLine = "*cl security*" OR CommandLine = "*cl system*" OR CommandLine = "*cl application*") 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have administrative privileges to run `wevtutil.exe` and clear event logs.
- **Required Artifacts:** Process creation logs, command-line arguments, event log status.

---

## Considerations

- Investigate the user account and host context for the detected `wevtutil.exe` activity.
- Review for additional signs of compromise, such as privilege escalation or ransomware deployment.
- Correlate with other suspicious events, such as file deletion or backup removal.
- Check for legitimate maintenance or troubleshooting activity that may explain the log clearing.

---

## False Positives

False positives may occur if:

- Administrators are performing legitimate log maintenance or troubleshooting.
- Automated scripts or IT tools are used for scheduled log management.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the log clearing.
2. Review recent activity for signs of compromise or evidence removal.
3. Check for additional indicators of malicious activity or privilege escalation.
4. Isolate affected systems if malicious activity is confirmed.
5. Restore event logs from backups if possible.

---

## References

- [MITRE ATT&CK: T1070.001 – Indicator Removal on Host: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-09 | Initial Detection | Created hunt query to detect Windows event log clearing using wevtutil.exe                 |
