# Detection of Yurei-Specific Ransomware Indicators (File Extensions and Ransom Notes)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** CRITICAL

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Yurei-Indicators-T1486
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low (post-encryption, high-fidelity)

---

## Hunt Analytics

This hunt detects Yurei-specific indicators including the `.Yurei` file extension and the creation of `_README_Yurei.txt` ransom notes. This provides high-fidelity detection with near-zero false positives but is reactive (post-encryption). Use in conjunction with behavioral queries for earlier detection.

Detected artifacts include:
- Creation or presence of files with the `.Yurei` extension
- Creation of Yurei ransom notes named `_README_Yurei.txt`

These artifacts are characteristic of Yurei’s encryption impact phase.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1486       | -            | Data Encrypted for Impact                     |

---

## Hunt Query Logic

This query identifies Yurei ransomware artifacts through direct file indicator matching:

- Phase 1: Detects `.Yurei` encrypted file creation
- Phase 2: Detects `_README_Yurei.txt` ransom note creation
- Correlates presence of both to categorize active encryption vs. single indicator

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Yurei Ransomware Specific Artifacts (File Extensions and Ransom Notes)
// Description: Detects Yurei-specific indicators including the .Yurei file extension and _README_Yurei.txt ransom notes.
// MITRE ATT&CK TTP ID: T1486

config case_sensitive = false  
| dataset = xdr_data  
| filter event_type = ENUM.FILE  

// Phase 1: Detect .Yurei encrypted file creation  
| alter yurei_encrypted_file = if(  
        action_file_extension = ".Yurei",  
        true, false  
  )  

// Phase 2: Detect Yurei ransom note creation  
| alter yurei_ransom_note = if(  
        action_file_name = "_README_Yurei.txt",  
        true, false  
  )  

// Filter for any Yurei-specific indicator  
| filter yurei_encrypted_file = true or yurei_ransom_note = true  

// Enrichment  
| alter severity = "CRITICAL",  
        detection_category = if(yurei_encrypted_file = true and yurei_ransom_note = true, "Yurei Ransomware - Active Encryption",  
                           if(yurei_encrypted_file = true, "Yurei Ransomware - Encrypted Files",  
                           "Yurei Ransomware - Ransom Note")),  
        risk_score = 100,  
        mitre_technique = "T1486",  
        ioc_type = if(yurei_encrypted_file = true, ".Yurei file extension", "Yurei ransom note")  

| fields _time,  
         agent_hostname,  
         actor_process_image_name,  
         actor_process_command_line,  
         action_file_path,  
         action_file_name,  
         action_file_extension,  
         actor_effective_username,  
         severity,  
         detection_category,  
         ioc_type,  
         risk_score  

| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | File                | File Creation          |
| Cortex       | xdr_data         | File                | File Modification      |

---

## Execution Requirements

- **Required Permissions:** Standard file write permissions (varies by impacted directories)
- **Required Artifacts:** File creation/modification telemetry including file name and extension

---

## Considerations

- This detection is inherently reactive (post-encryption). Immediately triage and contain upon detection.
- Correlate with pre-encryption behaviors (VSS deletion, event log wiping, CIM/WMI lateral movement) for full kill-chain visibility.
- Investigate the process responsible for creating the `.Yurei` files or ransom notes.
- Validate scope of impact across hosts and file shares.

---

## False Positives

- Extremely rare. Potential edge cases include:
  - Security testing where `.Yurei` artifacts are simulated
  - Manual file renaming for testing or research

**Mitigation:** Restrict simulation activities to isolated environments and tune exclusions for known red team exercises.

---

## Recommended Response Actions

1. **Immediate Isolation:** Isolate affected endpoints to stop further encryption.
2. **Process Termination:** Identify and terminate the process creating `.Yurei` files.
3. **Scope Assessment:** Enumerate all directories and shares containing `.Yurei` files and ransom notes.
4. **Hunt for Pre-Encryption Indicators:** Run companion hunts for VSS deletion, event log wiping, and CIM/WMI lateral movement.
5. **Backup Restoration:** Restore from immutable/air-gapped backups; verify integrity before restoring.
6. **Credential Rotation:** Rotate credentials for affected accounts; disable compromised accounts.
7. **Forensic Preservation:** Collect memory dumps, process lists, and relevant logs for post-incident analysis.
8. **Engage Incident Response:** Escalate to IR team; coordinate communication and legal/compliance actions.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-10 | Initial Detection | Created hunt query to detect Yurei-specific ransomware artifacts (extensions and notes)    |
