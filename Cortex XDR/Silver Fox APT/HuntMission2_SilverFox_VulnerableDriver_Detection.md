# Silver Fox APT - Malicious Driver Loading and BYOVD Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-SilverFox-VulnerableDriver
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt identifies the loading of vulnerable drivers used by Silver Fox APT for their BYOVD (Bring Your Own Vulnerable Driver) attacks. It specifically targets the WatchDog Antimalware drivers (amsdk.sys, wamsdk.sys) and Zemana Anti-Malware drivers (ZAM.exe) that the group exploits to gain kernel-level privileges. The query also detects the creation of associated Windows services and registry modifications used to load these drivers, including the distinctive "Amsdk_Service" service name used by the threat actor. Detected behaviors include:

- Loading of vulnerable drivers like amsdk.sys, wamsdk.sys, ZAM.exe, or Amsdk_Service.sys
- Creation of services with command lines containing "sc create Amsdk_Service"
- Registry modifications to keys related to "Amsdk_Service" or "Termaintor" services

These techniques are associated with defense evasion, persistence, privilege escalation, and hijacking execution flow.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1574       | T1574.013    | Hijack Execution Flow: KPP Bypass            |
| TA0003 - Persistence         | T1543       | T1543.003    | Create or Modify System Process: Windows Service |
| TA0005 - Defense Evasion     | T1112       |              | Modify Registry                               |
| TA0004 - Privilege Escalation| T1548       |              | Abuse Elevation Control Mechanism            |

---

## Hunt Query Logic

This query identifies suspicious driver loading and service creation by looking for:

- Load image events for vulnerable drivers (amsdk.sys, wamsdk.sys, ZAM.exe, Amsdk_Service.sys)
- Process events with command lines creating "Amsdk_Service" (excluding auth_id 999 to reduce noise)
- Registry events modifying keys for "Amsdk_Service" or "Termaintor" services

These patterns are indicative of Silver Fox APT's BYOVD techniques for kernel privilege escalation.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
dataset = xdr_data 
| filter event_type = ENUM.LOAD_IMAGE or event_type = ENUM.REGISTRY or event_type = ENUM.PROCESS 
| filter ( 
    // Vulnerable driver loading 
    (event_type = ENUM.LOAD_IMAGE and ( 
        action_module_path contains "amsdk.sys" or 
        action_module_path contains "wamsdk.sys" or 
        action_module_path contains "ZAM.exe" or 
        action_module_path contains "Amsdk_Service.sys" 
    )) 
    or 
    // Service creation for driver loading (suppress noisy auth_id 999) 
    (event_type = ENUM.PROCESS 
        and actor_process_command_line contains "sc create Amsdk_Service" 
        and actor_process_auth_id != "999" 
    ) 
    or 
    // Registry modifications for driver service 
    (event_type = ENUM.REGISTRY and ( 
        action_registry_key_name contains "\Services\Amsdk_Service" or 
        action_registry_key_name contains "\Services\Termaintor" 
    )) 
) 
| fields event_timestamp, event_type, action_module_path, actor_process_command_line, 
         action_registry_key_name, action_registry_value_name, action_registry_key_name, actor_process_image_name, 
         actor_process_auth_id, causality_actor_process_image_name 
| sort desc event_timestamp 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |
| Cortex XSIAM|    xdr_data       | Module             | Module Load            |
| Cortex XSIAM|    xdr_data       | Windows Registry   | Windows Registry Key Modification |

---

## Execution Requirements

- **Required Permissions:** Administrator or SYSTEM privileges to load drivers and modify registry/services.
- **Required Artifacts:** Driver load logs, process creation logs, registry modification logs.

---

## Considerations

- Review the source and context of the driver loading and service creation for legitimacy.
- Correlate with user activity, installation logs, or known vulnerable software to determine if the activity is malicious.
- Investigate any associated processes or network activity for signs of exploitation.
- Validate if the drivers or services are associated with known vulnerable software or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Legitimate use of WatchDog or Zemana Anti-Malware software.
- System maintenance or updates involving these drivers/services.
- Custom or third-party software using similar naming conventions.

---

## Recommended Response Actions

1. Investigate the driver loading, service creation, and registry modifications for intent and legitimacy.
2. Analyze associated processes and network activity for signs of exploitation.
3. Review system logs for signs of compromise or privilege escalation.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor loading of vulnerable drivers and creation of suspicious services.

---

## References

- [MITRE ATT&CK: T1574.013 – Hijack Execution Flow: KPP Bypass](https://attack.mitre.org/techniques/T1574/013/)
- [MITRE ATT&CK: T1543.003 – Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK: T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [MITRE ATT&CK: T1548 – Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-09-04 | Initial Detection | Created hunt query to detect Silver Fox APT vulnerable driver loading and BYOVD          |
