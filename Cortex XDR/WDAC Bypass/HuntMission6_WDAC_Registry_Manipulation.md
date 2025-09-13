# Detection of WDAC Registry Policy Modifications

## Severity or Impact of the Detected Behavior
- **Risk Score:** 86
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-RegistryManipulation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects **registry modifications that configure WDAC policies**, particularly those that indicate the deployment of malicious or unauthorized configurations via **local registry settings** or **Group Policy Objects (GPOs)**.  

Registry modifications in `DeviceGuard`, `CodeIntegrity`, or WDAC-specific paths can alter how application control is enforced, allowing attackers to deploy **malicious policies or weaken enforcement mechanisms**.  

Detected behaviors include:

- Modification of registry values like `ConfigCIPolicyFilePath`, `DeployConfigCIPolicy`, and virtualization-based security settings.  
- Deployment of WDAC policies through **network shares, Temp directories, Downloads, or User paths**.  
- Suspicious redirection of WDAC policy files from trusted system directories.  

---

## ATT&CK Mapping

| Tactic                  | Technique   | Subtechnique | Technique Name                                   |
|-------------------------|-------------|--------------|-------------------------------------------------|
| TA0004 - Privilege Escalation | T1484   | T1484.001    | Domain Policy Modification: Group Policy Modification |
| TA0005 - Defense Evasion| T1112       | -            | Modify Registry                                 |

---

## Hunt Query Logic

The query surfaces registry modifications to WDAC-related keys and values. Any modification outside of trusted sources (e.g., `System32`) or from suspicious paths (`Temp`, `Users`, `Downloads`) may indicate tampering or malicious deployment.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Title: WDAC Registry Policy Manipulation Detection 
// Description: Detects registry modifications related to WDAC policy deployment 
// MITRE ATT&CK TTP ID: T1484.001, T1112

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE 

| filter action_registry_key_name contains "DeviceGuard" or  
        action_registry_key_name contains "CodeIntegrity" or  
        action_registry_key_name contains "WDAC"  

| filter action_registry_value_name in (  
    "ConfigCIPolicyFilePath", "DeployConfigCIPolicy", "RequirePlatformSecurityFeatures",  
    "EnableVirtualizationBasedSecurity", "HypervisorEnforcedCodeIntegrity"  
)  

| alter  
    policy_source = if( 
        action_registry_data contains "C:\Windows\System32", "Local System", 
        if(action_registry_data contains "C:", "Local Drive", "Network Share") 
    ), 
    gpo_deployment = if(  
        action_registry_key_name contains "Policies\Microsoft\Windows\DeviceGuard",  
        "GPO Deployment", "Local Configuration"  
    ),  
    suspicious_path = if(  
        action_registry_data contains "\Temp\" or  
        action_registry_data contains "\Users\" or  
        action_registry_data contains "\Downloads\",  
        "Suspicious", "Normal"  
    )  

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line,  
         action_registry_key_name, action_registry_value_name, action_registry_data,  
         policy_source, gpo_deployment, suspicious_path, actor_effective_username  

| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | Registry            | Registry Keys/Values   |

---

## Execution Requirements

- **Required Permissions:** Administrative privileges are required to alter WDAC registry policy keys.  
- **Required Artifacts:** Registry event telemetry and process metadata.  

---

## Considerations

- WDAC registry modifications should only occur via **authorized administrative activity** or **GPO updates**.  
- Attackers may abuse registry changes to redirect policy paths to malicious files or disable virtualization-based protections.  

---

## False Positives

False positives may occur from:  
- Legitimate WDAC policy deployments via GPO.  
- Authorized administrators testing policies in lab environments.  
- Security management tools setting WDAC parameters.  

---

## Tuning Recommendations

- Whitelist **policy management systems and accounts** known to perform WDAC-related changes.  
- Track **change windows** to avoid false positives during scheduled rollouts.  
- Correlate with **file system logs** for WDAC policy artifacts to verify authenticity.  

---

## Recommended Response Actions

1. Investigate the process/user responsible for setting WDAC registry keys.  
2. Validate whether the change correlates with IT-approved WDAC deployments.  
3. Ensure policy file paths point only to **trusted system directories**.  
4. Roll back unauthorized registry changes and re-enforce proper policy baselines.  
5. Correlate with network and file events to identify potential compromise attempts.  

---

## References

- [MITRE ATT&CK: T1484.001 – Domain Policy Modification](https://attack.mitre.org/techniques/T1484/001/)  
- [MITRE ATT&CK: T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)  
- [Microsoft WDAC Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/wdac-and-applocker-overview)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                        |
|---------|------------|-------------------|------------------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | WDAC registry manipulation detection query with suspicious path analysis.    |
