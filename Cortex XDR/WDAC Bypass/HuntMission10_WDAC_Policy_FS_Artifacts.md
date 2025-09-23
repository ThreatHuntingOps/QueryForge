# Detection of WDAC Policy File System Manipulation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 87
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-PolicyFSArtifacts
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects **file system artifacts associated with WDAC policy manipulation**, focusing on stealth techniques that adversaries use to conceal, masquerade, or manipulate WDAC policies. By monitoring file attributes and timestamps, analysts can identify attempts to weaken or bypass policy controls.

Detected behaviors include:

- **Timestomping** of WDAC policy files (`SiPolicy.p7b`) or other files in `CodeIntegrity`.  
- **Hidden/System attributes** set on WDAC policy files.  
- **Unusual file size anomalies**, which may indicate corrupt or malicious payloads.  
- **Policy file masquerading**, where files in `CodeIntegrity` are not named `SiPolicy.p7b`.  
- **Decoy/log files** created in Code Integrity paths to distract investigators.  

---

## ATT&CK Mapping

| Tactic                  | Technique   | Subtechnique | Technique Name                                   |
|-------------------------|-------------|--------------|-------------------------------------------------|
| TA0005 - Defense Evasion| T1070       | T1070.006    | Indicator Removal on Host: Timestomp            |
| TA0005 - Defense Evasion| T1564       | T1564.001    | Hide Artifacts: Hidden Files and Directories    |

---

## Hunt Query Logic

This query reviews file system metadata related to **WDAC policy files** and highlights suspicious anomalies across **timestamps, sizes, attributes, and file naming conventions**.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: WDAC Policy File System Artifacts Detection 
// Description: Detects file system manipulation of WDAC policy files 
// MITRE ATT&CK TTP ID: T1070.006, T1564.001 

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = ENUM.FILE and (event_sub_type = ENUM.FILE_WRITE or event_sub_type = ENUM.FILE_SET_ATTRIBUTE) 

| filter action_file_path contains "CodeIntegrity" or action_file_name = "SiPolicy.p7b"  

| alter  
    timestomp_detected = if(  
        action_file_create_time != action_file_write_time and  
        to_integer(action_file_write_time) < to_integer(action_file_create_time),  
        "Potential Timestomp", "Normal"  
    ),  
    hidden_attributes = if(  
        action_file_attributes in (2, 4, 6, 18, 20, 22, 34, 36, 38),  
        "Hidden/System", "Normal"  
    ),  
    size_anomaly = if(  
        action_file_size < 1000 or action_file_size > 100000,  
        "Unusual Size", "Normal Size"  
    ),  
    masquerading = if(  
        action_file_name != "SiPolicy.p7b" and action_file_path contains "CodeIntegrity",  
        "Potential Masquerading", "Standard Name"  
    ),  
    decoy_files = if(  
        action_file_name in ("app.log", "system.log", "debug.log") and  
        action_file_path contains "CodeIntegrity",  
        "Decoy File", "Normal"  
    )  

| filter timestomp_detected = "Potential Timestomp" or   
        hidden_attributes = "Hidden/System" or  
        size_anomaly = "Unusual Size" or  
        masquerading = "Potential Masquerading" or  
        decoy_files = "Decoy File"  

| fields _time, agent_hostname, actor_process_image_name, action_file_path, action_file_name,  
         timestomp_detected, hidden_attributes, size_anomaly, masquerading, decoy_files,  
         action_file_size, action_file_create_time, action_file_write_time  

| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | File                | File Write / Attribute Change |

---

## Execution Requirements

- **Required Permissions:** Elevated rights to modify system policy file paths.  
- **Required Artifacts:** File creation logs, file attribute modifications, size/timestamp metadata.  

---

## Considerations

- **System maintenance utilities** may occasionally adjust timestamps or file attributes.  
- WDAC policy logs need baselining to reduce noise from routine policy changes.  
- Cross-correlate with process creation logs for **EDR or attacker tool execution**.  

---

## False Positives

False positives may occur in cases of:  
- Legitimate backup or synchronization operations.  
- Legitimate administrators modifying WDAC configurations.  
- Corruption or recovery utilities interacting with Code Integrity directories.  

---

## Tuning Recommendations

- Establish **baseline profiles** for authentic WDAC policy files.  
- Incorporate **hash validation** for trusted vs. untrusted policies.  
- Apply **temporal correlation** to separate manual tampering from scheduled maintenance.  

---

## Recommended Response Actions

1. Investigate policy files in `CodeIntegrity` flagged for timestomping, hidden attributes, or decoy naming.  
2. Validate the integrity and signing of `SiPolicy.p7b`.  
3. Check associated actor processes to determine abuse vs. legitimate modification.  
4. Roll back suspicious policy changes to restore baseline protections.  
5. Hunt environment-wide for evidence of **systematic policy tampering**.  

---

## References

- [MITRE ATT&CK: T1070.006 – Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006/)  
- [MITRE ATT&CK: T1564.001 – Hide Artifacts: Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/)  
- [Microsoft: WDAC Policy Protections](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/wdac-and-applocker-overview)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                        |
|---------|------------|-------------------|------------------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | File system-level WDAC policy manipulation detection, incl. timestomping and hidden attributes. |
