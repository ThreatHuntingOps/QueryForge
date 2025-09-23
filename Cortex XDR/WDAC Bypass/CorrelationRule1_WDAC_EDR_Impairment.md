# WDAC Weaponization - EDR Impairment Attack Sequence

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Analytics Metadata

- **ID:** CorrelationRule-Windows-WDAC-EDR-Impairment
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Analytics

This correlation rule detects a complete multi-stage defense evasion sequence focused on **malicious WDAC (Windows Defender Application Control) policy deployment followed by EDR service impairment and potential system reboot**. This attack chain represents a sophisticated attempt at **defense evasion** by both enforcing malicious kernel policies and disabling endpoint security services.  

Detected behaviors include:

- **Stage 1:** Deployment of a malicious WDAC policy (via `SiPolicy.p7b` or policies written to `CiPolicies` paths).  
- **Stage 2:** EDR service impairment, via direct process termination or registry modification (e.g., disabling startup by setting service start type to `4`).  
- **Stage 3:** System reboot triggered through malicious shutdown commands to enforce the malicious policy and kill defenses.  

This correlation requires a WDAC malicious deployment indicator along with either EDR impairment or reboot activity, ensuring **high-confidence detection**.

---

## ATT&CK Mapping

| Tactic                    | Technique   | Subtechnique | Technique Name                                   |
|---------------------------|-------------|--------------|-------------------------------------------------|
| TA0005 - Defense Evasion  | T1562       | T1562.001    | Impair Defenses: Disable or Modify Tools        |
| TA0004 - Privilege Escal. | T1484       | T1484.001    | Domain Policy Modification                      |
| TA0005 - Defense Evasion  | T1070       | T1070.006    | Indicator Removal: Timestomp                   |

---

## Query Logic

This rule correlates events for WDAC policy deployment with EDR disruption and system reboot behaviors. The **presence of Stage 1 (policy deployment)** plus **Stage 2 (EDR impairment) or Stage 3 (reboot)** is required for detection.

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data

// Stage 1: WDAC Policy Deployment Detection
| alter policy_flag = if(
        event_type = FILE and
        (action_file_name = "SiPolicy.p7b" or action_file_path contains "CiPolicies") and
        actor_process_image_name not in ("TrustedInstaller.exe", "svchost.exe"),
        true, false
  ),
  policy_timestamp = _time,
  policy_hostname = agent_hostname,
  policy_process = actor_process_image_name,
  policy_file_path = action_file_path,
  deployment_method = if(actor_process_command_line contains "localhost", "Local SMB",
                     if(actor_process_command_line contains "copy", "File Copy", 
                     "Direct Write"))

// Stage 2: EDR Service Impairment Detection
| alter edr_flag = if(
        (event_type = PROCESS and 
         (actor_process_image_name contains "crowdstrike" or
          actor_process_image_name contains "sentinelone" or
          actor_process_image_name contains "defender" or
          actor_process_image_name contains "symantec" or
          actor_process_image_name contains "carbon" or
          actor_process_image_name contains "falcon")) or
        (event_type = REGISTRY and
         action_registry_key_name contains "Services" and
         action_registry_value_name = "Start" and
         action_registry_data = "4"),
        true, false
  ),
  edr_timestamp = _time,
  edr_hostname = agent_hostname,
  impairment_type = if(event_type = PROCESS, "Process Kill", "Registry Disable"),
  edr_target = if(actor_process_image_name != null, actor_process_image_name, action_registry_key_name)

// Stage 3: System Reboot Detection
| alter reboot_flag = if(
        event_type = PROCESS and 
        actor_process_command_line contains "shutdown" and
        (actor_process_command_line contains "/r" or 
         actor_process_command_line contains "/restart"),
        true, false
  ),
  reboot_timestamp = _time,
  reboot_hostname = agent_hostname,
  reboot_method = if(event_type = PROCESS, "Command Line", "System Event")

// Correlation Logic
| filter policy_flag = true and (edr_flag = true or reboot_flag = true)

// Output Fields
| fields _time, agent_hostname, policy_process, policy_file_path, deployment_method,
         impairment_type, edr_target, reboot_method
| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name  | ATT&CK Data Source  | ATT&CK Data Component       |
|----------------|-------------|---------------------|-----------------------------|
| Cortex XSIAM   | xdr_data    | File                | File Write                  |
| Cortex XSIAM   | xdr_data    | Process             | Process Creation/Termination |
| Cortex XSIAM   | xdr_data    | Registry            | Registry Keys/Values        |

---

## Execution Requirements

- **Required Permissions:** Elevated privileges for WDAC policy deployment and registry modification.  
- **Required Artifacts:** File, process, registry telemetry.  

---

## Considerations

- The deployment of `SiPolicy.p7b` outside of authorized installers is highly suspicious.  
- Correlation with reboot ensures detection of full evasion sequence.  
- EDR service impairment attempts indicate intent to disable security protections.  

---

## False Positives

- Legitimate WDAC policy deployment by administrators.  
- EDR service updates that might temporarily stop/start security services.  

---

## Recommended Response Actions

1. Immediately isolate the endpoint to contain potential malware spread.  
2. Validate WDAC policy integrity and configuration against baselines.  
3. Investigate the process responsible for policy deployment.  
4. Review EDR service impairment attempts; restart services as needed.  
5. Conduct forensic investigation across host and Active Directory.  

---

## References

- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)  
- [MITRE ATT&CK: T1484.001 – Domain Policy Modification](https://attack.mitre.org/techniques/T1484/001/)  
- [MITRE ATT&CK: T1070.006 – Indicator Removal on Host: Timestomp](https://attack.mitre.org/techniques/T1070/006/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                |
|---------|------------|-------------------|----------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Added correlation for WDAC malicious deployment with EDR impairment. |
