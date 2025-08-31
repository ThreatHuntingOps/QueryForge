# Detection of Suspected Persistence via Crontab, Init.d, and systemd on Linux

## Hunt Analytics Metadata

- **ID:** `HuntQuery-Linux-Persistence-Behavioral`
- **Operating Systems:** `LinuxEndpoint`, `LinuxServer`
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects behavioral indicators of malicious persistence on Linux systems, focusing on techniques used by malware families such as SNOWLIGHT and system_worker. The query identifies suspicious use of crontab for scheduled tasks, service creation via systemd or init.d, and deployment of binaries to `/tmp/` or `/usr/bin/` directories. These behaviors are commonly observed in campaigns by UNC5174 and similar threat actors. The detection is IOC-agnostic, enabling identification of new or evolving malware strains that leverage these persistence mechanisms.

Detected behaviors include:

- Creation or modification of crontab entries, especially with `@reboot` or frequent schedules
- Use of `systemctl` or `chkconfig` to enable or add services
- Copying or deploying binaries to `/usr/bin/` or `/tmp/` directories
- Modifying file permissions to make binaries executable in suspicious locations
- Creation or modification of systemd service files

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0003 - Persistence         | T1053.003   | —            | Scheduled Task/Job: Cron                               |
| TA0004 - Privilege Escalation| T1543.002   | —            | Create or Modify System Process: Systemd Service       |
| TA0003 - Persistence         | T1037.004   | —            | Boot or Logon Initialization Scripts: rc.common        |
| TA0010 - Exfiltration        | T1105       | —            | Ingress Tool Transfer                                  |
| TA0002 - Execution           | T1204       | —            | User Execution                                         |

---

## Hunt Query Logic

This query identifies suspicious process creation events that match behavioral patterns associated with Linux persistence techniques:

- Crontab modifications with `@reboot` or frequent schedules
- Service management commands (`systemctl`, `chkconfig`)
- File operations targeting `/usr/bin/` or `/tmp/`
- Permission changes to make files executable in these locations
- Creation of new systemd service files

These patterns are frequently leveraged by Linux malware to maintain persistence and evade detection.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 OR event_simpleName=ProcessCreate  
| ((CommandLine = "*crontab*" AND CommandLine = "*@reboot*") OR (CommandLine = "*crontab*" AND CommandLine = "* * * * * *") OR (CommandLine = "*systemctl*" AND (CommandLine = "*enable*" OR CommandLine = "*start*" OR CommandLine = "*daemon-reload*")) OR (CommandLine = "*chkconfig*" AND CommandLine = "*add*") OR (CommandLine = "*cp*" AND TargetFileName = "/usr/bin/*") OR (CommandLine = "*chmod*" AND CommandLine = "*+x*" AND (TargetFileName = "/tmp/*" OR TargetFileName = "/usr/bin/*")) OR (TargetFileName = "/etc/systemd/system/*.service"))  
| ImageFileName = "*bash" OR ImageFileName = "*sh"   
```

---

## Data Sources

| Log Provider | Event ID | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|--------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A      | ProcessCreate      | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker or user must have permissions to modify crontab, create/initiate services, or deploy binaries to system directories.
- **Required Artifacts:** Process creation logs, command-line arguments, file operation logs.

---

## Considerations

- Review the context of crontab and service modifications—legitimate system administration may trigger similar events.
- Investigate the source and content of binaries deployed to `/usr/bin/` or `/tmp/`.
- Correlate with user activity and known maintenance windows to reduce false positives.
- Examine the parent process and user context for suspicious privilege escalation.

---

## False Positives

False positives may occur if:

- System administrators are performing legitimate maintenance or automation tasks.
- Configuration management tools (e.g., Ansible, Puppet) are deploying or updating services and scripts.
- Custom monitoring or backup scripts are scheduled via crontab or systemd.

---

## Recommended Response Actions

1. Investigate the process and user responsible for the suspicious activity.
2. Review the content and origin of any new or modified crontab entries or service files.
3. Analyze deployed binaries for malicious functionality.
4. Check for additional persistence mechanisms or lateral movement.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1053.003 – Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
- [MITRE ATT&CK: T1543.002 – Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
- [MITRE ATT&CK: T1037.004 – Boot or Logon Initialization Scripts: rc.common](https://attack.mitre.org/techniques/T1037/004/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1204 – User Execution](https://attack.mitre.org/techniques/T1204/)
- [UNC5174’s evolution in China’s ongoing cyber warfare: From SNOWLIGHT to VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-23 | Initial Detection | Created hunt query to detect behavioral Linux persistence techniques via crontab, systemd, and init.d |
