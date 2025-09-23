# Silver Fox APT - Registry and Service-Based Persistence Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-SilverFox-Persistence
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt identifies persistence mechanisms established by Silver Fox APT, specifically targeting the creation of the "Termaintor" and "Amsdk_Service" Windows services. It detects registry modifications, service creation commands, and file system artifacts in the characteristic "C:\Program Files\RunTime" directory. The query also identifies the specific service configurations used by the threat actor to ensure their malicious loader and vulnerable driver are executed on system startup. Detected behaviors include:

- Service creation commands for "Termaintor" or "Amsdk_Service"
- Registry modifications to service keys or Run keys containing "RunTime"
- File creations in "C:\Program Files\RunTime" for "RuntimeBroker.exe" or "Amsdk_Service.sys"

These techniques are associated with persistence through Windows services and registry autostart.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence         | T1543       | T1543.003    | Create or Modify System Process: Windows Service |
| TA0003 - Persistence         | T1547       | T1547.001    | Boot or Logon Autostart Execution: Registry Run Keys |
| TA0005 - Defense Evasion     | T1112       |              | Modify Registry                               |

---

## Hunt Query Logic

This query identifies persistence mechanisms by looking for:

- Process events with command lines creating "Termaintor" or "Amsdk_Service" services
- Registry events modifying keys for these services or Run keys with "RunTime"
- File events creating specific files in "C:\Program Files\RunTime"

These patterns are indicative of Silver Fox APT's service-based and registry-based persistence.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.REGISTRY or event_type = ENUM.PROCESS or event_type = ENUM.FILE  
| filter (  
    // Detect service creation via sc.exe  
    (event_type = ENUM.PROCESS and (  
        actor_process_command_line contains "sc create Termaintor" or  
        actor_process_command_line contains "sc create Amsdk_Service"  
    )) or  
    // Detect registry modifications for persistence  
    (event_type = ENUM.REGISTRY and (  
        action_registry_key_name contains "\Services\Termaintor" or  
        action_registry_key_name contains "\Services\Amsdk_Service" or  
        (action_registry_key_name contains "\CurrentVersion\Run" and action_registry_value_name contains "RunTime")  
    )) or  
    // Detect file creation in persistence directory  
    (event_type = ENUM.FILE and (  
        action_file_path contains "C:\Program Files\RunTime\" and  
        (action_file_name = "RuntimeBroker.exe" or action_file_name = "Amsdk_Service.sys")  
    ))  
)  
| fields event_timestamp, event_type, actor_process_command_line, action_registry_key_name,  
         action_registry_value_name, action_registry_value_type, action_file_path, action_file_name,  
         actor_process_image_name  
| sort desc event_timestamp 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |
| Cortex XSIAM|    xdr_data       | Windows Registry   | Windows Registry Key Modification |
| Cortex XSIAM|    xdr_data       | File               | File Creation          |

---

## Execution Requirements

- **Required Permissions:** Administrator privileges to create services, modify registry, and write to Program Files.
- **Required Artifacts:** Process creation logs, registry modification logs, file creation logs.

---

## Considerations

- Review the source and context of the service creation, registry changes, and file placements for legitimacy.
- Correlate with user activity, installation logs, or known persistence mechanisms to determine if the activity is malicious.
- Investigate any associated processes or network activity for signs of compromise.
- Validate if the services, registry entries, or files are associated with known threat actor indicators.

---

## False Positives

False positives may occur if:

- Legitimate software creates similar services or registry entries.
- System maintenance or updates involve these paths or names.
- Custom or third-party tools use "RunTime" or similar directories.

---

## Recommended Response Actions

1. Investigate the service creation, registry modifications, and file creations for intent and legitimacy.
2. Analyze associated processes and network activity for signs of persistence.
3. Review system logs for signs of compromise.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Remove or disable suspicious services and registry entries.

---

## References

- [MITRE ATT&CK: T1543.003 – Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-09-04 | Initial Detection | Created hunt query to detect Silver Fox APT persistence mechanisms                        |
