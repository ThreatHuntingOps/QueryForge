# Detection of Suspicious Process Creation by Python (Potential Injection Target)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-PythonProcessInjection
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects instances where `python.exe` or `run.py` spawns processes such as `notepad.exe`, `calc.exe`, or `svchost.exe`. Such behavior is highly unusual in legitimate workflows and is a strong indicator of process injection or process hollowing techniques. Attackers may use Python to inject code into benign processes to evade detection, escalate privileges, or maintain persistence on the system.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                                      |
| TA0005 - Defense Evasion     | T1055.013   | —            | Process Injection: Process Hollowing                   |

---

## Hunt Query Logic

This query identifies suspicious process creation events where Python is the parent process:

- The process name is `notepad.exe`, `calc.exe`, or `svchost.exe` (case-insensitive)
- The parent process is `python.exe` or `run.py` (case-insensitive)

Such patterns are rarely seen in legitimate environments and are often associated with process injection or other advanced attack techniques.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
// Title: Notepad, Calculator, or Svchost Spawned by Python or run.py
// Description: Detects notepad.exe, calc.exe, or svchost.exe processes whose parent process is python.exe or run.py, which may indicate suspicious process spawning or process injection.
// MITRE ATT&CK TTP ID: T1059.006

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "notepad.exe"
        or action_process_image_name = "calc.exe"
        or action_process_image_name = "svchost.exe"
    )
    and (
        actor_process_image_name = "python.exe"
        or actor_process_image_name = "run.py"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute Python scripts and spawn new processes.
- **Required Artifacts:** Process creation logs, parent-child process relationships, command-line arguments.

---

## Considerations

- Investigate the parent Python script or process for injection or malicious logic.
- Review the spawned process for injected code or unusual behavior.
- Correlate with other endpoint activity for signs of persistence or privilege escalation.
- Check for additional suspicious process creation events linked to Python.

---

## False Positives

False positives are rare but may occur if:

- Legitimate automation or testing scripts use Python to launch benign processes (uncommon in most environments).

---

## Recommended Response Actions

1. Investigate the parent Python script or process.
2. Analyze the spawned process for signs of injection or malicious activity.
3. Review system and security logs for additional suspicious process creation events.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized scripts or payloads.

---

## References

- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1055.013 – Process Hollowing](https://attack.mitre.org/techniques/T1055/013/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-02 | Initial Detection | Created hunt query to detect suspicious process creation by Python (potential injection target) |
