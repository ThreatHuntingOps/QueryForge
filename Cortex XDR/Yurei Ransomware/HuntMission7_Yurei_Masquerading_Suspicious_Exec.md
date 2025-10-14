# Detection of Process Execution from Suspicious Locations with Masquerading Names

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (suspicious path), 85 (non-standard location without explicit suspicious path)
- **Severity:** HIGH

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Masquerading-Suspicious-Exec-T1036
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low (depends on code signing telemetry)

---

## Hunt Analytics

This hunt detects processes with legitimate-sounding Windows system file names executing from non-standard or suspicious locations. Yurei masquerades as legitimate Windows processes (e.g., `WindowsUpdate.exe`, `svchost.exe`) to avoid detection. The query flags execution from temp directories, user directories, removable or non-system drives, and UNC paths. It excludes known-good Microsoft-signed binaries when telemetry is available.

Detected behaviors include:
- System-like process names running outside standard system directories
- Executables staged and launched from Temp, Downloads, Users\Public, removable drives, or network shares
- Non-Microsoft-signed binaries using Windows system process names

---

## ATT&CK Mapping

| Tactic                         | Technique   | Subtechnique | Technique Name                             |
|-------------------------------|-------------|--------------|-------------------------------------------|
| TA0005 - Defense Evasion      | T1036       | .003         | Masquerading: Rename System Utilities     |
| TA0002 - Execution            | T1204       | .002         | User Execution: Malicious File            |

---

## Hunt Query Logic

This query identifies masquerading through name and path analysis combined with code signing checks:

### Target Names
- System-like process names and Yurei-known masquerades:
  - `svchost.exe`, `csrss.exe`, `lsass.exe`, `smss.exe`, `winlogon.exe`,
    `services.exe`, `wininit.exe`, `taskhost.exe`, `taskhostw.exe`,
    `RuntimeBroker.exe`, `dwm.exe`, `conhost.exe`,
    `WindowsUpdate.exe`, `System32_Backup.exe`, `MicrosoftEdgeUpdate.exe`

### Standard Locations (Excluded)
- `\\Windows\\System32\\`, `\\Windows\\SysWOW64\\`, `\\Windows\\WinSxS\\`

### Suspicious Locations
- `\\Temp\\`, `\\AppData\\Local\\Temp\\`, `\\Users\\Public\\`, `\\Downloads\\`
- Non-system/local drive roots and removable drives: `^[A-Z]:\\`, `^[E-Z]:\\`
- UNC paths: `^\\\\[^\\\\]+\\.*`

### Signing Exclusions
- Exclude processes with signature status SIGNED and vendor "Microsoft Corporation"

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious Process Execution with System File Masquerading
// Description: Detects system-like process names executing from non-standard or suspicious locations, excluding Microsoft-signed binaries where possible.
// MITRE ATT&CK TTP IDs: T1036.003, T1204.002

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 

// Target system-like process names and known masquerades 
| filter actor_process_image_name in ( 
    "svchost.exe","csrss.exe","lsass.exe","smss.exe","winlogon.exe", 
    "services.exe","wininit.exe","taskhost.exe","taskhostw.exe", 
    "RuntimeBroker.exe","dwm.exe","conhost.exe", 
    "WindowsUpdate.exe","System32_Backup.exe","MicrosoftEdgeUpdate.exe" 
  ) 

// Not in standard Windows system locations 
| filter not ( 
    actor_process_image_path contains "\Windows\System32\" 
    or actor_process_image_path contains "\Windows\SysWOW64\" 
    or actor_process_image_path contains "\Windows\WinSxS\" 
  ) 

// Suspicious execution paths 
| alter suspicious_path = if( 
    actor_process_image_path contains "\Temp\" 
    or actor_process_image_path contains "\AppData\Local\Temp\" 
    or actor_process_image_path contains "\Users\Public\" 
    or actor_process_image_path contains "\Downloads\" 
    or actor_process_image_path ~= "^[A-Z]:\\" 
    or actor_process_image_path ~= "^[E-Z]:\\" 
    or actor_process_image_path ~= "^\\[^\\]+\\.*", 
    true, false 
  ) 

// Exclude legit (signed by Microsoft). Status is enum; vendor is string in many tenants. 
| filter not ( 
    actor_process_signature_status = ENUM.SIGNED 
    and actor_process_signature_vendor = "Microsoft Corporation" 
  ) 

// Enrichment 
| alter risk_score = if(suspicious_path = true, 95, 85) 
| alter severity = "HIGH", 
        detection_category = "Masquerading - System Process from Suspicious Location", 
        mitre_technique = "T1036.003" 

| fields _time, 
         agent_hostname, 
         actor_process_image_name, 
         actor_process_image_path, 
         actor_process_command_line, 
         actor_effective_username, 
         actor_process_signature_status, 
         actor_process_signature_vendor, 
         suspicious_path, 
         severity, 
         detection_category, 
         risk_score 

| sort desc risk_score 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Standard user execution; elevation may occur post-launch
- **Required Artifacts:** 
  - Process creation telemetry with image path and command-line
  - Code signing status and vendor metadata
  - User context and parent process

---

## Considerations

- **Path Regexes:** The generic `^[A-Z]:\\` matches all local drive roots; use with care and rely on standard path exclusions above.
- **UNC Paths:** Include remote execution contexts (e.g., execution from network shares).
- **Signing Trust:** Some malware may be signed with stolen certificates; treat signed-but-unknown vendors with caution.
- **Masquerading:** Legitimate Microsoft-signed binaries should be excluded; non-Microsoft vendors using these names are highly suspicious.
- **Temp Staging:** Many malware families stage in Temp; correlate with recent file writes in the same directory.

---

## False Positives

- Third-party updaters that temporarily stage binaries outside system directories
- Portable applications executed from Downloads or removable drives
- IT scripts/tools packaged with system-like names for compatibility

**Mitigation:** Maintain allowlists for trusted updaters and deployment tools; refine by publisher, file hash, and known paths.

---

## Recommended Response Actions

1. **Immediate Investigation:** Confirm if execution is sanctioned or part of a known deployment.
2. **Kill Process:** Terminate suspicious processes that are not signed by Microsoft or expected vendors.
3. **Quarantine Binary:** Isolate the executable and compute hashes for reputation checks.
4. **Trace Lineage:** Review parent process, command-line, and file origin (download source, share path, USB origin).
5. **Correlate with Yurei Indicators:** Check for related activity:
   - VSS/backup deletion (Query 1)
   - Event log deletion (Query 2)
   - CIM/WMI lateral movement (Query 3)
   - Mass file encryption (Query 4)
   - Yurei-specific indicators: `.Yurei` files, `_README_Yurei.txt` (Query 5)
   - SMB file drops (Query 6)
   - USB propagation (Query 7)
6. **Containment:** Isolate host if malicious activity is confirmed.
7. **Credential Hygiene:** Rotate affected credentials and review admin group memberships.
8. **Persistence Check:** Hunt for persistence mechanisms (Run keys, Scheduled Tasks, Services, WMI subscriptions).
9. **Forensic Preservation:** Collect memory, prefetch, AmCache, shimcache, and $MFT artifacts.

---

## References

- [MITRE ATT&CK: T1036.003 – Masquerading: Rename System Utilities](https://attack.mitre.org/techniques/T1036/003/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-10 | Initial Detection | Created hunt query for suspicious process execution with system file masquerading          |

