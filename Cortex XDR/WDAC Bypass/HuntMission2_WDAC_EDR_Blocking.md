# Detection of Suspicious WDAC Policy File Modifications

## Severity or Impact of the Detected Behavior
- **Risk Score:** 87
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-PolicyTampering-Metadata
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects **suspicious creation or modification of WDAC policy files** (`SiPolicy.p7b`, `CiPolicies\Active`) using **metadata-based indicators**. These events may suggest tampering attempts designed to disable or weaken **EDR/AV protections**.  

Since file content analysis is not available in this dataset, the rule leverages **metadata signals** such as path, filename, process ancestry, file size, and hash. Unauthorized writes to WDAC directories are **high-confidence indicators of malicious activity** and should trigger further investigation.

Detected behaviors include:

- Unauthorized processes writing to `System32\CodeIntegrity` or `CiPolicies\Active`.  
- Creation of suspicious or empty WDAC policy files.  
- Unexpected policy file modifications that may conceal EDR-blocking rules.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                   |
|-------------------------------|-------------|--------------|-------------------------------------------------|
| TA0005 - Defense Evasion      | T1562       | T1562.001    | Impair Defenses: Disable or Modify Tools        |
| TA0004 - Privilege Escalation | T1484       | T1484.001    | Domain Policy Modification: Group Policy Modification |

---

## Hunt Query Logic

This query identifies **non-system processes** modifying WDAC policy files. Events are flagged if the action targets `SiPolicy.p7b` or `CiPolicies\Active` paths and the process is not a trusted deployment mechanism (e.g., `TrustedInstaller.exe`, `svchost.exe`).

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Malicious WDAC Policy File Detection 
// Description: Detects suspicious modification of WDAC policy files (SiPolicy.p7b, CiPolicies\Active) by unauthorized processes.
// MITRE ATT&CK: T1562.001, T1484.001

config case_sensitive = false  

| dataset = xdr_data 

| filter event_type = ENUM.FILE 

| filter action_file_name = "SiPolicy.p7b"  
        or action_file_path contains "CiPolicies\Active" 

| filter not (actor_process_image_name in ("TrustedInstaller.exe", "svchost.exe")) 

| alter 
    policy_directory = if(action_file_path contains "System32\CodeIntegrity", "Primary", "Secondary"), 
    enforce_mode = if(action_file_size > 0, "Present", "Suspicious Empty"), 
    policy_size = action_file_size 

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, 
         action_file_path, policy_directory, enforce_mode, policy_size, 
         action_file_md5, actor_effective_username 

| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | File                | File Write / Modification |

---

## Execution Requirements

- **Required Permissions:** Elevated privileges for policy modification.  
- **Required Artifacts:** File system logs, process creation logs, file metadata (hash, size).  

---

## Considerations

- **Empty policy files** could indicate attackers attempting to create placeholder or corrupted WDAC policies to bypass enforcement.  
- Events identified by this hunt should be followed by full **file retrieval and offline inspection** for hidden EDR-blocking rules.  
- Correlate with **registry entries** pointing to custom WDAC file paths for added confidence.  

---

## False Positives

False positives may occur in cases of:  
- **Legitimate WDAC policy updates** or deployments via enterprise change management.  
- **Windows Update modifications** to enforce or update default WDAC policies.  

---

## Recommended Response Actions

1. Validate the policy modification event against change-control records.  
2. Investigate the **actor process** responsible for modifying WDAC files.  
3. Retrieve the suspicious policy file and conduct **offline inspection**.  
4. Restore a known-good WDAC baseline and re-enforce policy if tampering is confirmed.  
5. Consider isolating affected systems until policy integrity is restored.  

---

## References

- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)  
- [MITRE ATT&CK: T1484.001 – Domain Policy Modification](https://attack.mitre.org/techniques/T1484/001/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                       |
|---------|------------|-------------------|-----------------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Metadata-based hunting for suspicious WDAC policy file injection/tampering. |
