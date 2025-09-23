# Silver Fox APT - Legitimate Driver Abuse and Process Hollowing Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-SilverFox-DefenseEvasion
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects defense evasion techniques employed by Silver Fox APT, including the abuse of legitimate signed drivers to bypass security controls and process masquerading. It identifies the characteristic pattern of loading vulnerable drivers followed by the termination of security processes, signature timestamp manipulation for hash evasion, and the use of legitimate process names in suspicious locations. The query correlates these events to detect the systematic disabling of endpoint security products. Detected behaviors include:

- Loading of signed vulnerable drivers like amsdk.sys or wamsdk.sys
- Process masquerading with RuntimeBroker.exe in non-standard paths like "C:\Program Files\RunTime"
- Anti-analysis network checks to ip-api.com

These techniques are associated with hijacking execution flow, masquerading, subverting trust controls, and impairing defenses.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1574       | T1574.013    | Hijack Execution Flow: KPP Bypass            |
| TA0005 - Defense Evasion     | T1036       |              | Masquerading                                 |
| TA0005 - Defense Evasion     | T1553       |              | Subvert Trust Controls                       |
| TA0005 - Defense Evasion     | T1497       |              | Virtualization/Sandbox Evasion               |
| TA0005 - Defense Evasion     | T1562       | T1562.001    | Impair Defenses: Disable or Modify Tools     |

---

## Hunt Query Logic

This query identifies defense evasion techniques by looking for:

- Load image events for signed vulnerable drivers (amsdk.sys, wamsdk.sys)
- Process events for masquerading RuntimeBroker.exe in suspicious paths
- Process events with command lines containing "ip-api.com" for anti-analysis checks

These patterns are indicative of Silver Fox APT's use of legitimate driver abuse and process hollowing for evasion.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.LOAD_IMAGE or event_type = ENUM.PROCESS  
| filter (  
    // Detect signed vulnerable drivers being loaded  
    (event_type = ENUM.LOAD_IMAGE and (  
        (action_module_path contains "amsdk.sys" or action_module_path contains "wamsdk.sys") and  
        action_module_signature_status = ENUM.SIGNED  
    )) or  
    // Detect process masquerading  
    (event_type = ENUM.PROCESS and (  
        actor_process_image_name = "RuntimeBroker.exe" and   
        actor_process_image_path !~= ".*\System32\.*" and  
        actor_process_image_path contains "\Program Files\RunTime\"  
    )) or  
    // Detect anti-analysis network checks  
    (event_type = ENUM.PROCESS and actor_process_command_line contains "ip-api.com")  
)  
| fields event_timestamp, event_type, action_module_path, action_module_signature_status,  
          actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_image_sha256  
| sort desc event_timestamp 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Module             | Module Load            |
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Administrator privileges to load drivers and execute processes in restricted paths.
- **Required Artifacts:** Driver load logs, process creation logs, command-line arguments.

---

## Considerations

- Review the source and context of the driver loading and process execution for legitimacy.
- Correlate with security product logs to check for disabling or modification.
- Investigate network connections to ip-api.com for anti-analysis intent.
- Validate if the drivers or processes are associated with known evasion techniques or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Legitimate use of signed drivers for security software.
- Benign processes named RuntimeBroker.exe in custom directories.
- Legitimate network checks to geolocation services.

---

## Recommended Response Actions

1. Investigate the driver loading and process masquerading for intent and legitimacy.
2. Analyze network activity for anti-analysis behaviors.
3. Review security product status for signs of impairment.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor loading of vulnerable drivers and suspicious processes.

---

## References

- [MITRE ATT&CK: T1574.013 – Hijack Execution Flow: KPP Bypass](https://attack.mitre.org/techniques/T1574/013/)
- [MITRE ATT&CK: T1036 – Masquerading](https://attack.mitre.org/techniques/T1036/)
- [MITRE ATT&CK: T1553 – Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)
- [MITRE ATT&CK: T1497 – Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497/)
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-09-04 | Initial Detection | Created hunt query to detect Silver Fox APT defense evasion techniques                    |
