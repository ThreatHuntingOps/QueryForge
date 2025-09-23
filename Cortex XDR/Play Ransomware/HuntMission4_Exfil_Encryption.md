# Detection of WinRAR, WinSCP, and .PLAY File Extension Used in Play Ransomware Campaigns

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Cortex-PlayRansomware-ExfilEncryption
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious use of WinRAR for data compression, WinSCP for exfiltration, and signs of file encryption associated with Play ransomware. It flags rare or suspicious binaries using unique hashes per deployment, identifies creation of .RAR files, .PLAY encrypted files, and presence of ransom notes in atypical locations, such as `C:\Users\Public\Music`.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                            |
|-------------------------------|-------------|--------------|----------------------------------------------------------|
| TA0009 - Collection           | T1560.001   | —            | Archive Collected Data: Archive via Utility (WinRAR)     |
| TA0010 - Exfiltration         | T1048       | —            | Exfiltration Over Alternative Protocol (WinSCP/SFTP)     |
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact (.PLAY extension, ransom note) |
| TA0005 - Defense Evasion      | T1027       | —            | Obfuscated Files or Information (unique binary hash)     |

---

## Hunt Query Logic

This query identifies suspicious process activity related to Play ransomware data exfiltration and encryption:

- Use of WinRAR (`rar.exe`, `winrar`) for data compression
- Use of WinSCP (`winscp.exe`, `winscp`, `sftp`, `scp`) for exfiltration
- Creation or reference to `.PLAY` encrypted files
- Presence of ransom notes or files in `C:\Users\Public\Music`
- Unique SHA256 hash per binary execution to flag custom or obfuscated tools

These patterns are commonly seen in ransomware campaigns involving data theft and encryption.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_image_name contains "rar.exe"
    or actor_process_command_line contains "a *.rar"
    or actor_process_command_line contains "winrar"
| filter actor_process_image_name contains "winscp.exe"
    or actor_process_command_line contains "winscp"
    or actor_process_command_line contains "sftp"
    or actor_process_command_line contains "scp"
| filter actor_process_image_name contains ".PLAY"
    or actor_process_command_line contains ".PLAY"
| filter actor_process_image_path contains "\\Users\\Public\\Music\\"
| filter actor_process_image_sha256 != null
    and actor_process_image_name != ""
| fields agent_hostname, actor_process_image_name, actor_process_command_line, actor_process_image_path, actor_process_image_sha256, event_timestamp
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process execution events from Windows endpoints.
- **Required Artifacts:** Process execution logs, command line arguments, file hashes, target file names.

---

## Considerations

- Investigate the process path, command line, and file hash for evidence of custom or obfuscated tools.
- Validate the user context and parent process for additional signs of compromise.
- Correlate with other suspicious behaviors, such as data staging or network exfiltration.

---

## False Positives

False positives may occur if:
- Legitimate administrative or backup tools use WinRAR or WinSCP in similar ways.
- Internal IT scripts or software deployment tools create .RAR files or use SFTP for benign reasons.

---

## Recommended Response Actions

1. Investigate the process tree, command line, and file hash for malicious indicators.
2. Validate the legitimacy of the tool or script and its source.
3. Review related process activity, file creation, and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1560.001 – Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)
- [MITRE ATT&CK: T1048 – Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [#StopRansomware: Play Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-10 | Initial Detection | Created hunt query to detect Play ransomware data exfiltration and encryption tools         |
