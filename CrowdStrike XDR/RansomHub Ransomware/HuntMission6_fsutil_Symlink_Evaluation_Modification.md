# Detection of fsutil Used to Modify Symlink Evaluation

## Severity or Impact of the Detected Behavior

- **Risk Score:** 80  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-fsutil-SymlinkEval
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of `fsutil.exe` to modify symbolic link evaluation settings on Windows systems. Attackers may leverage these changes—specifically enabling `SymlinkEvaluation R2L:1` (remote-to-local) or `SymlinkEvaluation R2R:1` (remote-to-remote)—to facilitate lateral movement, bypass security controls, or manipulate file and directory permissions. Such modifications can enable unauthorized access to files or resources across network shares, and are rarely seen in normal administrative activity.

Detected behaviors include:

- Use of `fsutil.exe` with command-line arguments to enable remote-to-local or remote-to-remote symlink evaluation
- Attempts to alter default Windows security boundaries for symbolic links
- Potential setup for lateral movement or privilege escalation

These actions are often observed in advanced attacks where adversaries seek to expand their access or evade detection.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion      | T1222       | —            | File and Directory Permissions Modification   |

---

## Hunt Query Logic

This query identifies suspicious executions of `fsutil.exe` with command-line arguments that modify symlink evaluation settings, specifically enabling remote-to-local or remote-to-remote symlink evaluation.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    

| (FileName = "fsutil.exe")    

| (CommandLine = "*SymlinkEvaluation*R2L:1*" OR CommandLine = "*SymlinkEvaluation*R2R:1*") 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have administrative privileges to run `fsutil.exe` and modify symlink settings.
- **Required Artifacts:** Process creation logs, command-line arguments, system configuration changes.

---

## Considerations

- Investigate the user account and host context for the detected `fsutil.exe` activity.
- Review for additional signs of lateral movement or privilege escalation.
- Correlate with other suspicious events, such as file or directory permission changes.
- Check for legitimate administrative or troubleshooting activity that may explain the modification.

---

## False Positives

False positives may occur if:

- Administrators are performing legitimate troubleshooting or configuration changes.
- Automated scripts or IT tools are used for system hardening or compatibility adjustments.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the symlink evaluation modification.
2. Review recent activity for signs of lateral movement or privilege escalation.
3. Check for additional indicators of compromise or unauthorized access.
4. Revert symlink evaluation settings to secure defaults if malicious activity is confirmed.
5. Monitor for further attempts to modify system security boundaries.

---

## References

- [MITRE ATT&CK: T1222 – File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-09 | Initial Detection | Created hunt query to detect fsutil symlink evaluation modification                        |
