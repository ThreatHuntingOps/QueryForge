# Detection of Anomalous Process Opening Critical System Processes

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Anomalous-TokenTheft
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects a key privilege escalation technique where an attacker's process opens a high-privilege system process (like `svchost.exe` or `explorer.exe`) to interact with it, often to steal its access token. Since endpoint logs may not specify the access rights of the handle being opened, this query instead focuses on identifying when an unexpected or anomalous parent process performs this action. It achieves this by excluding a list of common, legitimate Windows processes known to interact with `svchost.exe` and `explorer.exe`, thereby reducing noise and highlighting suspicious behavior consistent with the Chaos ransomware TTP.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0004 - Privilege Escalation | T1134       | .001         | Access Token Manipulation: Token Impersonation/Theft |
| TA0005 - Defense Evasion      | T1134       | .001         | Access Token Manipulation: Token Impersonation/Theft |

---

## Hunt Query Logic

This query identifies potential token theft by looking for an anomalous parent-child relationship:
- It first identifies when a critical system process like `svchost.exe` or `explorer.exe` is started.
- It then filters out any events where the parent process (`actor_process_image_name`) is a known, legitimate system process that normally performs this action.
- Any remaining events represent an anomaly where a non-standard process is interacting with these high-privilege targets, which is a strong indicator of malicious activity.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Anomalous Process Opening Critical System Processes for Token Stealing
// MITRE ATT&CK TTP ID: T1134.001

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START  
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name in ("svchost.exe", "explorer.exe") 
    and actor_process_image_name not in ( 
        "services.exe", 
        "userinit.exe", 
        "winlogon.exe", 
        "lsass.exe", 
        "smss.exe", 
        "csrss.exe", 
        "wininit.exe", 
        "dwm.exe", 
        "taskhostw.exe", 
        "taskmgr.exe" 
    ) 
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, actor_process_image_path, actor_process_command_line, action_process_image_name, event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The attacker must already be executing code on the host.
- **Required Artifacts:** Process creation logs with accurate parent-child process relationships.

---

## Considerations

- **Behavioral Detection:** This is a behavioral hunt that relies on an exclusion list. Its effectiveness depends on the accuracy of that list.
- **Tuning Required:** The exclusion list of legitimate parent processes may need to be tuned for your specific environment. You may need to add other legitimate third-party applications (e.g., security agents, management tools) to the list to reduce false positives.
- **The Real Culprit:** The key process to investigate in any alert is the parent (`actor_process_image_name`), not the child (`action_process_image_name`).

---

## False Positives

- False positives are possible and will likely come from legitimate third-party software that is not included in the exclusion list.
- Each new finding should be investigated. If it is found to be legitimate, its process name should be considered for addition to the exclusion list to improve the fidelity of the hunt.

---

## Recommended Response Actions

1.  **Investigate the Parent Process:** The focus of the investigation must be on the `actor_process_image_name`. Analyze its name, path, hash, and command line.
2.  **Collect and Analyze Binary:** If the parent process seems suspicious, collect the binary for forensic analysis in a sandbox.
3.  **Isolate Host:** If the parent process is confirmed to be malicious, isolate the host to prevent further privilege escalation or lateral movement.
4.  **Hunt for Parent Process:** Use the hash and name of the malicious parent process to hunt for its presence across the environment.

---

## References

- [MITRE ATT&CK: T1134.001 – Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)
---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created behavioral hunt for anomalous processes opening system targets. |
