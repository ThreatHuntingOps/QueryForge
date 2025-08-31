# Detection of Anubis Ransomware File and Directory Discovery with Exclusion List (Noise-Reduced)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnubisFileDiscovery
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects suspicious processes that enumerate files and directories while referencing multiple Anubis exclusion folders and exhibiting other Anubis-specific behaviors. The detection is designed to reduce false positives from legitimate system activity by excluding known system and backup processes. This approach focuses on processes that both reference multiple Anubis-excluded directories (windows, system32, programdata) and use Anubis-specific command-line parameters, significantly increasing the likelihood of detecting true ransomware activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery           | T1083       | —            | File and Directory Discovery                   |
| TA0005 - Defense Evasion     | T1562.001   | —            | Impair Defenses: Disable or Modify Tools      |
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |

---

## Hunt Query Logic

This query identifies process execution events that meet multiple criteria:
1. Use Anubis-specific command-line parameters (/KEY=, /WIPEMODE, /elevated, /PATH=, /PFAD=)
2. Reference multiple system directories commonly excluded by ransomware (windows, system32, programdata)
3. Are not common system or backup processes (explorer.exe, svchost.exe, backup.exe, msmpeng.exe)

This multi-layered approach significantly reduces noise while maintaining high detection accuracy for Anubis ransomware activity.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
// Title: Suspicious Process Command Line Switches with System Path Indicators
// Description: Detects processes with suspicious command line switches and references to Windows, System32, and ProgramData, excluding common system processes. This may indicate privilege escalation, staging, or data exfiltration attempts.
// MITRE ATT&CK TTP ID: T1548

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_command_line contains "/key="
        or action_process_image_command_line contains "/wipemode"
        or action_process_image_command_line contains "/elevated"
        or action_process_image_command_line contains "/path="
        or action_process_image_command_line contains "/pfad="
    )
    and (
        action_process_image_command_line contains "windows"
        and action_process_image_command_line contains "system32"
        and action_process_image_command_line contains "programdata"
    )
    and not (action_process_image_name in ("explorer.exe", "svchost.exe", "backup.exe", "msmpeng.exe"))
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute processes with custom command-line arguments and directory enumeration capabilities.
- **Required Artifacts:** Process creation logs with full command-line capture and file system access logs.

---

## Considerations

- Investigate the process tree and parent process for initial access vectors.
- Review file system activity for signs of encryption or deletion patterns.
- Correlate with network activity for potential data exfiltration or C2 communication.
- Examine excluded directories for signs of tampering or modification.

---

## False Positives

False positives are very unlikely due to the multi-layered filtering approach, but may occur if:
- Custom administrative tools use similar command-line parameters and directory references.
- Third-party security or backup tools are misconfigured to use these specific patterns.

---

## Recommended Response Actions

1. Isolate the affected endpoint immediately to prevent lateral movement.
2. Investigate the process tree and parent process for initial access vectors.
3. Review file system activity for signs of encryption, deletion, or modification patterns.
4. Collect forensic artifacts (memory, disk, logs) for detailed analysis.
5. Initiate incident response and recovery procedures immediately.
6. Check for signs of data exfiltration or C2 communication.

---

## References

- [MITRE ATT&CK: T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [Anubis: A Closer Look at an Emerging Ransomware with Built-in Wiper](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-23 | Initial Detection | Created noise-reduced hunt query to detect Anubis ransomware file and directory discovery with exclusion filtering |
