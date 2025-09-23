# Detection of Python Execution with Campaign-Specific Arguments

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-PythonCampaignArgs
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the execution of `python.exe` with a specific command-line pattern associated with a known campaign: `run.py -i *.bin -k *.txt`. This pattern suggests the use of a Python script (`run.py`) that takes a binary input file (`-i *.bin`) and a key or configuration file (`-k *.txt`), which is characteristic of certain malware or data exfiltration tools. Such targeted detection is valuable for identifying campaign-specific activity and tracking threat actor TTPs.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1059.006   | —            | Command and Scripting Interpreter: Python              |
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                         |

---

## Hunt Query Logic

This query identifies suspicious executions of `python.exe` with the following command-line indicators:

- The process name is `python.exe` (case-insensitive)
- The command line includes `run.py`, `-i`, a `.bin` file, `-k`, and a `.txt` file

Such patterns are rarely seen in legitimate workflows and are often associated with targeted malware campaigns or data exfiltration tools.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Python Executable Running run.py with Specific Arguments
// Description: Detects python.exe processes executing run.py with -i and -k flags, and referencing .bin and .txt files in the command line, which may indicate staged or automated script execution.
// MITRE ATT&CK TTP ID: T1059.006

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name = "python.exe"
    and action_process_image_command_line contains "run.py"
    and action_process_image_command_line contains "-i"
    and action_process_image_command_line contains ".bin"
    and action_process_image_command_line contains "-k"
    and action_process_image_command_line contains ".txt"
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

- **Required Permissions:** User or attacker must be able to execute Python scripts and provide command-line arguments.
- **Required Artifacts:** Python scripts, process creation logs, command-line arguments, input and key files.

---

## Considerations

- Investigate the `run.py` script and its source for malicious logic.
- Review the `.bin` and `.txt` files for sensitive or exfiltrated data.
- Correlate with other endpoint activity for signs of lateral movement or persistence.
- Check for additional files or payloads associated with the campaign.

---

## False Positives

False positives are rare but may occur if:

- Legitimate development or automation scripts use similar command-line patterns (uncommon in most environments).

---

## Recommended Response Actions

1. Investigate the `run.py` script and its source.
2. Analyze command-line arguments for suspicious or campaign-specific activity.
3. Review system and security logs for additional signs of compromise.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized scripts or payloads.

---

## References

- [MITRE ATT&CK: T1059.006 – Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-02 | Initial Detection | Created hunt query to detect Python execution with campaign-specific arguments              |
