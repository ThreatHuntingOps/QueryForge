# Detection of Mimikatz and Nirsoft CredentialsFileView Execution

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-CredDump-ToolExec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the execution of well-known credential dumping tools, specifically Mimikatz and Nirsoft’s CredentialsFileView. These tools are frequently used by threat actors to harvest credentials from memory or local files after gaining initial access to a system. The presence of these binaries in process creation logs is a strong indicator of post-exploitation activity and a potential precursor to lateral movement, privilege escalation, or data exfiltration.

Detected behaviors include:

- Execution of `mimikatz.exe` or `credentialsfileview.exe`
- Attempts to extract credentials from LSASS memory or local credential stores
- Commonly observed in ransomware, red team, and advanced persistent threat (APT) operations

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0006 - Credential Access    | T1003       | —            | OS Credential Dumping                         |
| TA0006 - Credential Access    | T1003.001   | —            | OS Credential Dumping: LSASS Memory           |

---

## Hunt Query Logic

This query identifies suspicious executions of credential dumping tools by matching process creation events for `mimikatz.exe` or `credentialsfileview.exe`. Such activity is rarely seen in legitimate environments and should be investigated immediately.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "mimikatz.exe"
        or action_process_image_name = "credentialsfileview.exe"
    )
| fields _time, agent_hostname, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to execute binaries and access credential stores.
- **Required Artifacts:** Process creation logs, binary hashes, command-line arguments.

---

## Considerations

- Investigate the user account and host context for the detected tool execution.
- Review for additional signs of compromise, such as privilege escalation or lateral movement.
- Correlate with other suspicious events, such as password changes or new account creation.
- Check for legitimate red team or security testing activity that may explain the execution.

---

## False Positives

False positives may occur if:

- Security teams or red teams are running credential dumping tools for authorized testing.
- Automated security validation tools deploy these binaries as part of compliance checks.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the tool execution.
2. Review recent activity for signs of credential theft or lateral movement.
3. Check for additional indicators of compromise or privilege escalation.
4. Isolate affected systems if malicious activity is confirmed.
5. Reset credentials and review access policies as needed.

---

## References

- [MITRE ATT&CK: T1003 – OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect Mimikatz and CredentialsFileView execution                    |
