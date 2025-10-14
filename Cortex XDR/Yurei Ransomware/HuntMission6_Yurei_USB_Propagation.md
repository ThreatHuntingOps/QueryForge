# Detection of Removable Media Propagation (USB Infection)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (Yurei/masquerading filename), 75 (generic executable to USB)
- **Severity:** HIGH or MEDIUM (based on filename risk)

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-USB-Propagation-T1091
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects executable files being written to removable drives (USB devices, external hard drives). Yurei drops `WindowsUpdate.exe` to USB drives as a propagation mechanism. The query identifies malware propagation to removable media, which can spread infections to air-gapped systems.

Detected behaviors include:
- Executable writes to removable drive letters (E:..Z:)
- Exclusion of Windows directory paths to reduce noise
- Suspicious filenames (Yurei-specific, masquerading as system binaries, or random 8–12 char names)

---

## ATT&CK Mapping

| Tactic                         | Technique   | Subtechnique | Technique Name                      |
|-------------------------------|-------------|--------------|------------------------------------|
| TA0008 - Lateral Movement     | T1091       | -            | Replication Through Removable Media|
| TA0005 - Defense Evasion      | T1036       | -            | Masquerading                       |

---

## Hunt Query Logic

This query identifies USB propagation through file write telemetry:

### Scope and Filtering
- FILE events with subtype WRITE or CREATE_NEW
- Paths starting with drive letters E: to Z: (typical removable media)
- Exclude paths containing `\\Windows\\` on the removable drive

### Suspicious Filename Detection
- **Yurei-specific:** `WindowsUpdate.exe`
- **Masquerading:** `svchost.exe`, `System32_Backup.exe`, `csrss.exe`, `lsass.exe`
- **Random naming:** 8–12 character lowercase alphanumeric `.exe` files

### Risk Scoring and Severity
- 95/HIGH for suspicious filenames
- 75/MEDIUM for generic executable writes to removable media

### Exclusions
- Known service accounts and tools: backup, sync, antivirus

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Executable Drops to Removable Media (USB/External Drives)
// Description: Detects executable files being written to removable drives. Yurei drops WindowsUpdate.exe to USB drives as a propagation mechanism.
// MITRE ATT&CK TTP IDs: T1091, T1036

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.FILE 
  and event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_CREATE_NEW) 

// Detect writes to removable drive letters (E:..Z:) and exclude Windows directory 
| filter action_file_path ~= "^[E-Z]:\\" 
  and action_file_path not contains "\Windows\" 

// Focus on executable files 
| filter action_file_extension in (".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta", ".scr", ".com") 

// Exclusions 
| filter not ( 
    actor_effective_username in ("DOMAIN\BackupSVC", "DOMAIN\AntivirusSVC") 
    or actor_process_image_name in ("backup.exe", "sync.exe", "antivirus.exe") 
  ) 

// Suspicious filenames 
| alter is_suspicious_filename = if( 
    action_file_name in ("WindowsUpdate.exe", "svchost.exe", "System32_Backup.exe", "csrss.exe", "lsass.exe") 
    or action_file_name ~= "^[a-z0-9]{8,12}\.exe$", 
    true, false 
  ) 

// Enrichment in separate stages to avoid same-stage reference issues 
| alter risk_score = if(is_suspicious_filename = true, 95, 75) 
| alter severity = if(is_suspicious_filename = true, "HIGH", "MEDIUM"), 
        detection_category = if(is_suspicious_filename = true, "Ransomware Propagation - USB Infection", 
                                "Suspicious Executable to Removable Media") 

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, 
         action_file_path, action_file_name, actor_effective_username, 
         is_suspicious_filename, severity, detection_category, risk_score 
| sort desc risk_score
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | File                | File Creation/Write    |

---

## Execution Requirements

- **Required Permissions:** Write access to removable drives
- **Required Artifacts:** 
  - File create/write telemetry with full path and filename
  - Process creation with command-line arguments
  - User context

---

## Considerations

- **Drive Letter Mapping:** Some environments map network or encrypted drives to letters E:..Z:. Validate device type via additional telemetry (WMI, Device Setup Class GUIDs).
- **Timing Correlation:** Look for process actions immediately before/after the file write (e.g., copying from temp directories).
- **Masquerading:** System-like filenames on removable media are highly suspicious.
- **User Behavior:** Validate if user is authorized to use removable media; check removable storage policies.

---

## False Positives

- Software updates distributed via USB in air-gapped environments
- Legitimate admin scripts/tools copied to USB for maintenance
- Backup/sync utilities writing to removable drives

**Mitigation:** Maintain allowlists for known tools and service accounts; correlate with maintenance windows and change tickets.

---

## Recommended Response Actions

1. **Immediate Investigation:** Determine whether the executable copy to USB is authorized.
2. **Quarantine Removable Media:** If malicious, quarantine the device to prevent spread.
3. **Analyze Dropped Executable:** Hash, reputation check, sandbox analysis.
4. **Source Attribution:** Trace back the originating process and user.
5. **Hunt for Related Activity:** Look for Yurei artifacts and previous queries’ indicators:
   - VSS/backup deletion commands
   - Event log deletion activity
   - CIM/WMI lateral movement
   - SMB file drops to shares
   - Files with `.Yurei` extension
   - `_README_Yurei.txt` ransom notes
6. **Policy Enforcement:** Enforce or tighten removable media usage policies and device control.
7. **Credential Hygiene:** Rotate credentials if compromise is suspected.
8. **Forensic Preservation:** Collect relevant logs and device metadata.
9. **Engage Incident Response:** Escalate to IR team as needed.

---

## References

- [MITRE ATT&CK: T1091 – Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
- [MITRE ATT&CK: T1036 – Masquerading](https://attack.mitre.org/techniques/T1036/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-10 | Initial Detection | Created hunt query to detect removable media propagation for Yurei ransomware               |

