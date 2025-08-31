
# Behavioral Detection of Unix/Linux Persistence via Cron Jobs and Service Abuse

## Hunt Analytics Metadata

- **ID:** `HuntQuery-CrowdStrike-UNIXPersistenceBehavior`
- **Operating Systems:** `Linux`, `Unix`
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt query is designed to detect potential persistence mechanisms on Unix/Linux systems used by threat actors, especially those leveraging cron jobs and service management systems like `systemd` and `init.d`. Rather than focusing on static indicators, it looks for behavioral traces of persistence including:

- Scheduled tasks using `@reboot` or timed cron expressions
- Creation or enabling of services via `systemctl` or `chkconfig`
- Dropping service definitions under `/etc/systemd/system/` or `/etc/init.d/`
- Execution from shells like `bash` or `sh`

These techniques are commonly employed in targeted intrusions to maintain access across reboots.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique     | Technique Name                                         |
|------------------------------|------------|------------------|--------------------------------------------------------|
| TA0003 - Persistence         | T1053.003  | —                | Scheduled Task/Job: Cron                               |
| TA0003 - Persistence         | T1543.002  | —                | Create or Modify System Process: Systemd Service       |
| TA0003 - Persistence         | T1543.004  | —                | Create or Modify System Process: Launch Daemon         |
| TA0003 - Persistence         | T1546.001  | —                | Event Triggered Execution: At (Linux)                  |
| TA0005 - Defense Evasion     | T1036      | —                | Masquerading                                           |

---

## Hunt Query Logic

This query highlights persistence-related process executions and file activities. Suspicious behaviors include:

- Scheduled cron entries like `@reboot` or hourly triggers
- Enabling or starting services with `systemctl`
- Creating services with `chkconfig`
- Dropping files in `/etc/systemd/system/` or `/etc/init.d/`

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 OR #event_simpleName=ProcessCreation 
| (CommandLine = "*@reboot*" OR CommandLine = "*crontab*" OR CommandLine = "*0 * * * **" OR CommandLine = "*systemctl enable*" OR CommandLine = "*systemctl start*" OR CommandLine = "*chkconfig*") 
| (CommandLine = "*service*" OR CommandLine = "*daemon-reload*" OR CommandLine = "*multi-user.target*") 
| (FilePath = "/etc/systemd/system/*" OR FilePath = "/etc/init.d/*") 
| ParentBaseFileName = "bash" OR ParentBaseFileName = "sh"
```

---

## Data Sources

| Log Provider | Event Name         | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------|---------------------|------------------------|
| Falcon       | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Access to cron jobs or root/service management permissions
- **Required Artifacts:** Command-line logs, service definition paths, cron tab entries

---

## Considerations

- Cross-reference service names and paths with legitimate system services
- Review service file contents for malicious payloads or commands
- Correlate activity with known initial access methods or other host artifacts

---

## False Positives

May be generated during:

- Administrative automation or patching procedures
- Deployment of custom software that uses legitimate persistence

---

## Recommended Response Actions

1. Review affected service files in `/etc/systemd/system/` and `/etc/init.d/`
2. Investigate crontab entries for unauthorized execution logic
3. Analyze parent-child process chains for unauthorized execution
4. Check timestamps and source IP (if remote setup is suspected)
5. Remove unauthorized persistence mechanisms and restore legitimate configurations

---

## References

- [MITRE ATT&CK: T1053.003 – Cron](https://attack.mitre.org/techniques/T1053/003/)
- [MITRE ATT&CK: T1543.002 – Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
- [MITRE ATT&CK: T1543.004 – Launch Daemon](https://attack.mitre.org/techniques/T1543/004/)
- [MITRE ATT&CK: T1546.001 – At (Linux)](https://attack.mitre.org/techniques/T1546/001/)
- [MITRE ATT&CK: T1036 – Masquerading](https://attack.mitre.org/techniques/T1036/)
- [UNC5174’s evolution in China’s ongoing cyber warfare: From SNOWLIGHT to VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-21 | Initial Detection | Added behavioral detection logic for cron/service-based persistence on Linux/Unix systems  |
