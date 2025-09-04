# Silver Fox APT - Spear-Phishing and Watering Hole Attack Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-SilverFox-InitialAccess
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the initial execution vectors used by Silver Fox APT, including spear-phishing attachments and watering hole compromises. The query focuses on detecting the execution of suspicious executables with names commonly used by the group, particularly those masquerading as legitimate system processes or appearing in unusual locations. It also identifies processes that perform immediate anti-analysis checks by contacting geolocation services, a distinctive behavior of Silver Fox's all-in-one loader. Detected behaviors include:

- Execution of RuntimeBroker.exe from non-standard locations (excluding System32 and SysWOW64)
- Processes with command lines containing "Runtime Broker" from non-system paths
- Unsigned EXEs (numeric signature status not equal to 1) not in Windows directories

These techniques are associated with initial access via phishing attachments and drive-by compromises, followed by execution of malicious files and evasion tactics.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0001 - Initial Access      | T1566       | T1566.001    | Phishing: Spearphishing Attachment            |
| TA0001 - Initial Access      | T1189       |              | Drive-by Compromise                           |
| TA0002 - Execution           | T1204       | T1204.002    | User Execution: Malicious File                |
| TA0005 - Defense Evasion     | T1497       |              | Virtualization/Sandbox Evasion                |
| TA0007 - Discovery           | T1614       |              | System Location Discovery                     |

---

## Hunt Query Logic

This query identifies suspicious process launches by looking for:

- RuntimeBroker.exe executed from paths outside System32 or SysWOW64
- Command lines containing "Runtime Broker" from non-system paths
- Unsigned EXEs (signature status != 1) not in Windows directories

These patterns are indicative of Silver Fox APT's use of masqueraded executables and anti-analysis behaviors.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
config case_sensitive = false  
| dataset = xdr_data  
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START  
| filter (  
    // RuntimeBroker.exe from suspicious locations (exclude System32 and SysWOW64)  
    (actor_process_image_name = "RuntimeBroker.exe" and actor_process_image_path !~= ".*\(System32|SysWOW64)\.*")  
    or   
    // Suspicious internal name from non-system paths  
    (actor_process_command_line contains "Runtime Broker" and actor_process_image_path !~= ".*\(System32|SysWOW64)\.*")  
    or   
    // EXEs that are not signed (numeric status)  
    (  
      (actor_process_image_name ~= "(?i)\.exe$" or actor_process_image_path ~= "(?i)\.exe$")  
      and coalesce(actor_process_signature_status, 0) != 1  
      and actor_process_image_path !~= ".*\Windows\.*" // optional: cut noise  
    )  
)  
| fields event_timestamp,  
         agent_hostname,  
         user_id,  
         actor_process_image_name,  
         actor_process_image_path,  
         actor_process_command_line,  
         actor_process_signature_vendor,  
         actor_process_signature_status,  
         causality_actor_process_image_sha256  
| sort desc event_timestamp 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute processes, potentially requiring elevated privileges for certain locations.
- **Required Artifacts:** Process creation logs, command-line arguments, file signature information, and path details.

---

## Considerations

- Review the source and context of the process and command line for legitimacy.
- Correlate with user activity, email, or download logs to determine if the activity is user-initiated or automated.
- Investigate any network connections for geolocation checks or other anti-analysis behaviors.
- Validate if the executable is associated with known malicious infrastructure or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Legitimate applications use similar process names or are unsigned but benign.
- System maintenance or updates trigger these patterns in non-standard paths.
- Custom or third-party software mimics these behaviors for legitimate purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Analyze network connections for signs of geolocation checks or C2.
3. Review user activity and system logs for signs of compromise.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious executables and paths.

---

## References

- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: T1189 – Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1497 – Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497/)
- [MITRE ATT&CK: T1614 – System Location Discovery](https://attack.mitre.org/techniques/T1614/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-09-04 | Initial Detection | Created hunt query to detect Silver Fox APT initial access vectors                        |
