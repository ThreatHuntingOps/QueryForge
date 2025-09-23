# Detection of Silent Application Uninstall via WMIC

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WMIC-Uninstall
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the use of the Windows Management Instrumentation command-line utility (`wmic.exe`) to silently uninstall an application. The Chaos ransomware group specifically uses this technique to remove security and multi-factor authentication (MFA) tools from a compromised system, thereby weakening its defenses before deploying the ransomware. The use of the `call uninstall` and `/nointeractive` flags are key indicators of a scripted, non-user-driven uninstallation process, which is highly indicative of malicious intent.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0005 - Defense Evasion      | T1562       | .001         | Impair Defenses: Disable or Modify Tools       |

---

## Hunt Query Logic

This query identifies silent uninstallation commands by looking for:
- The execution of `wmic.exe`.
- The presence of the `product` WMI class in the command line.
- The use of the `call uninstall` method.
- The inclusion of the `/nointeractive` switch, which suppresses any user prompts.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Silent Application Uninstall via WMIC
// Description: Detects the use of WMIC to silently uninstall applications, a technique used by Chaos RaaS to remove security and MFA tools.
// MITRE ATT&CK TTP ID: T1562.001

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "wmic.exe" 
    and action_process_image_command_line contains "product" 
    and action_process_image_command_line contains "call uninstall" 
    and action_process_image_command_line contains "/nointeractive" 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The attacker must have administrative privileges on the host to uninstall applications.
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- **Target Application:** The command line (`action_process_image_command_line`) will contain the name of the application being targeted for uninstallation. This is a critical piece of context.
- **Parent Process:** Understanding the parent process that spawned `wmic.exe` is key to identifying the attacker's script or tool.
- **WMIC Deprecation:** While `wmic.exe` is deprecated, it is still available on modern Windows systems and is frequently used by attackers for its power and ubiquity.

---

## False Positives

False positives may occur when:
- Legitimate enterprise software management tools (e.g., MECM/SCCM, Ivanti) use WMIC as part of their application deployment and removal scripts.
- Administrators use scripted methods for legitimate software removal.
The key to reducing false positives is to correlate this activity with other suspicious events and to understand what application is being removed. The uninstallation of a security tool is far more suspicious than the removal of a standard business application.

---

## Recommended Response Actions

1.  **Identify Target Application:** Immediately determine which application was uninstalled by examining the full command line.
2.  **Isolate Host:** If a security tool was removed, isolate the host immediately to prevent the attacker from achieving their next objective (e.g., deploying ransomware).
3.  **Investigate Actor:** Analyze the parent process and user account that initiated the WMIC command to trace the activity back to its source.
4.  **Re-enable Defenses:** Take immediate steps to reinstall or re-enable any security tools that were removed.
5.  **Hunt:** Hunt for similar WMIC uninstall activity across the environment.

---

## References

- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)
---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created hunt query to detect silent application uninstalls via WMIC. |
