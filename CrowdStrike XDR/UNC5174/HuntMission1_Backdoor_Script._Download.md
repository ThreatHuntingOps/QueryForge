# Detection of download_backd.sh Script Execution and Malicious Binary Deployment

## Hunt Analytics Metadata

- **ID:** `HuntQuery-CrowdStrike-UNC5174-DownloadBackdScript`
- **Operating Systems:** `LinuxEndpoint`, `Unix`
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt is designed to detect execution of the `download_backd.sh` script used by UNC5174 to stage and persist malware on compromised systems. The script leverages `curl` for remote payload download, adjusts execution permissions, and creates persistence via `crontab` and `systemd/init.d` service manipulation. It often introduces binaries like `dnsloger` and `system_worker` into the `/tmp` or `/usr/bin` directories, frequently attempting to blend in by using timestamp-based masquerading.

Detected behaviors include:

- Use of `curl -sL` with remote IP/domain delivery (`gooogleasia.com:8080`)
- Use of `chmod +x` in temporary directories
- Creation of persistence through `@reboot`, `systemctl`, or `chkconfig`
- Use of `touch --reference` to evade timestamp-based detection
- Execution of suspicious binaries (`dnsloger`, `system_worker`)

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                           |
|------------------------------|------------|---------------|----------------------------------------------------------|
| TA0002 - Execution            | T1059.004 | —             | Command and Scripting Interpreter: Unix Shell            |
| TA0011 - Command and Control  | T1105     | —             | Ingress Tool Transfer                                    |
| TA0005 - Defense Evasion      | T1055     | —             | Process Injection                                        |
| TA0003 - Persistence          | T1053.003 | —             | Scheduled Task/Job: Cron                                 |
| TA0003 - Persistence          | T1543.002 | —             | Create or Modify System Process: Systemd Service         |
| TA0003 - Persistence          | T1546.001 | —             | Event Triggered Execution: At (Linux)                    |
| TA0005 - Defense Evasion      | T1036.005 | —             | Masquerading: Match Legitimate Name or Location          |

---

## Hunt Query Logic

The query flags command executions involving:

- `curl` calls to known malicious infrastructure (`gooogleasia.com`)
- Attempts to make files executable (`chmod +x /tmp/*`)
- Persistence mechanisms like `crontab`, `@reboot`, `systemctl enable`, or `chkconfig`
- Timestamp manipulation using `touch --reference`
- File deployment or execution from `/tmp` and `/usr/bin`
- Execution of known UNC5174 binaries such as `dnsloger` or `system_worker`

These activities collectively indicate compromise and malicious automation for persistence and backdoor access.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 OR #event_simpleName=ProcessCreation 
| (CommandLine = "*curl -sL*gooogleasia.com:8080*" OR CommandLine = "*chmod +x /tmp/*") 
| (CommandLine = "*touch --reference=/usr/bin*" OR CommandLine = "*crontab -l*" OR CommandLine = "*@reboot*" OR CommandLine = "*systemctl enable*" OR CommandLine = "*chkconfig*") 
| (CommandLine = "*dnsloger*" OR CommandLine = "*system_worker*") 
| (FilePath = "/tmp/*" OR FilePath = "/usr/bin/*") 
| ParentBaseFileName = "bash"
```

---

## Data Sources

| Log Provider | Event Name        | ATT&CK Data Source | ATT&CK Data Component |
|--------------|-------------------|--------------------|------------------------|
| Falcon       | ProcessRollup2    | Process             | Process Creation       |
| Falcon       | ProcessCreation   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Shell script execution and ability to modify crontab or system services
- **Required Artifacts:** Bash script logs, binary files in `/tmp` or `/usr/bin`, persistence entries

---

## Considerations

- Verify the origin and hash of any binaries found in `/tmp` or `/usr/bin`
- Cross-check URLs and IPs contacted via `curl`
- Identify unauthorized changes to cron jobs or system services
- Monitor for repeated execution after reboot via scheduled tasks

---

## False Positives

This query may produce false positives if:

- Administrators or developers use similar scripts for automation
- System provisioning tools alter system services or use `crontab`
- Valid binaries are deployed temporarily for troubleshooting

---

## Recommended Response Actions

1. Quarantine the host if malicious files or unauthorized services are detected.
2. Extract and analyze payloads found in `/tmp` or `/usr/bin`.
3. Audit systemd and init.d service entries for unauthorized additions.
4. Check crontab entries for unauthorized scheduled tasks.
5. Investigate command-line history and user activity for context.

---

## References

- [MITRE ATT&CK: T1059.004 – Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1053.003 – Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
- [MITRE ATT&CK: T1543.002 – Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
- [MITRE ATT&CK: T1546.001 – At (Linux)](https://attack.mitre.org/techniques/T1546/001/)
- [MITRE ATT&CK: T1036.005 – Masquerading](https://attack.mitre.org/techniques/T1036/005/)
- [UNC5174’s evolution in China’s ongoing cyber warfare: From SNOWLIGHT to VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)

---

## Version History

| Version | Date       | Impact             | Notes                                                               |
|---------|------------|--------------------|---------------------------------------------------------------------|
| 1.0     | 2025-04-21 | Initial Detection | Created hunt for download_backd.sh script and persistence behaviors |
