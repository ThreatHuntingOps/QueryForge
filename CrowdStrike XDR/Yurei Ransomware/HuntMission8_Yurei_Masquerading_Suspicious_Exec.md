# Detection of Process Execution from Suspicious Locations with Masquerading Names

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (suspicious path), 85 (non-standard location without explicit suspicious path)
- **Severity:** HIGH

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Masquerading-Suspicious-Exec-T1036
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low (depends on code signing telemetry)
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Hunt Analytics

Detects system-like process names executing from non-standard or suspicious locations using CrowdStrike Falcon telemetry. Yurei masquerades as `WindowsUpdate.exe`, `svchost.exe`, etc. The hunt flags execution from temp/user dirs, removable or non-system drives, and UNC paths, excluding known-good Microsoft-signed binaries when telemetry allows.

Detected behaviors:
- System-like names running outside standard system directories
- Executables staged/launched from Temp, Downloads, Users\\Public, removable drives, or network shares
- Non-Microsoft-signed binaries using Windows system process names

---

## ATT&CK Mapping

| Tactic                     | Technique | Subtechnique | Technique Name                              |
|----------------------------|----------:|-------------:|---------------------------------------------|
| TA0005 - Defense Evasion   | T1036     | .003         | Masquerading: Rename System Utilities       |
| TA0002 - Execution         | T1204     | .002         | User Execution: Malicious File              |

---

## Hunt Query Logic

- Target names: `svchost.exe`, `csrss.exe`, `lsass.exe`, `smss.exe`, `winlogon.exe`, `services.exe`, `wininit.exe`, `taskhost(.exe|w.exe)`, `RuntimeBroker.exe`, `dwm.exe`, `conhost.exe`, `WindowsUpdate.exe`, `System32_Backup.exe`, `MicrosoftEdgeUpdate.exe`
- Exclude standard locations: `\\Windows\\System32\\`, `\\Windows\\SysWOW64\\`, `\\Windows\\WinSxS\\`
- Suspicious locations: Temp, Users\\Public, Downloads, drive roots (A:–Z:), UNC paths
- Signing exclusions: Exclude Microsoft-signed where available

---

## Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: Suspicious Process Execution with System File Masquerading
// Description: Detects system-like process names executing from non-standard or suspicious locations, excluding Microsoft-signed binaries where possible.
// MITRE ATT&CK: T1036.003, T1204.002

| #repo="base_sensor" event_platform="Win"
| #event_simpleName="ProcessRollup2"

// Target system-like process names and known masquerades (exact list, case-insensitive via regex)
| (ImageFileName=/\\(svchost\\.exe|csrss\\.exe|lsass\\.exe|smss\\.exe|winlogon\\.exe|services\\.exe|wininit\\.exe|taskhost\\.exe|taskhostw\\.exe|RuntimeBroker\\.exe|dwm\\.exe|conhost\\.exe|WindowsUpdate\\.exe|System32_Backup\\.exe|MicrosoftEdgeUpdate\\.exe)$/i)

// Not in standard Windows system locations
| (ImageFileName!=/\\Windows\\System32\\/i and ImageFileName!=/\\Windows\\SysWOW64\\/i and ImageFileName!=/\\Windows\\WinSxS\\/i)

// Suspicious execution paths
| suspicious_path := 0
| (
    ImageFileName=/\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Downloads\\/i
    or ImageFileName=/^[A-Z]:\\/i
    or ImageFileName=/^[E-Z]:\\/i
    or ImageFileName=/^\\\\[^\\]+\\/i
  ) | suspicious_path := 1

// Exclude legit Microsoft-signed where possible
// SignInfoFlags and *_meaning fields vary by tenant; prefer fields ending with _meaning for readable values when present.
| is_ms_signed := 0
| SignInfoFlags_meaning=/Signed/i and ImageSubsystem_meaning=* | is_ms_signed := 1
| (is_ms_signed=0) or (is_ms_signed=1 and Tags!~/Microsoft Corporation/i)

// Enrichment
| risk_score := 85
| suspicious_path=1 | risk_score := 95

| severity := "HIGH"
| detection_category := "Masquerading - System Process from Suspicious Location"
| mitre_technique := "T1036.003, T1204.002"

// Output
| select([
    @timestamp,
    aid,
    ComputerName,
    ImageFileName,
    CommandLine,
    UserName,
    ParentBaseFileName,
    ParentProcessId,
    suspicious_path,
    severity,
    detection_category,
    risk_score,
    mitre_technique,
    SignInfoFlags,
    SignInfoFlags_meaning
])
| sort([risk_score], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                 | ATT&CK Data Source | Data Component     |
|--------------------|------------------------------------------|--------------------|--------------------|
| CrowdStrike Falcon | base_sensor: ProcessRollup2 (processes)  | Process            | Process Creation   |

Field notes:
- Identity: aid, ComputerName; user: UserName
- Process fields: ImageFileName, CommandLine, ParentBaseFileName, ParentProcessId
- Signing fields vary by tenant: SignInfoFlags / SignInfoFlags_meaning, Tags (publisher)

---

## Execution Requirements
- **Required Permissions:** Standard user execution; elevation may occur post-launch
- **Required Artifacts:** Process creation telemetry with image path and command-line; code signing status/vendor; user context and parent

---

## Considerations
- `^[A-Z]:\\` is broad; rely on standard path exclusions and suspicious-path constraints.
- UNC paths indicate execution from shares; correlate with SMB file-drop hunts.
- Treat signed-but-unknown vendors with caution; stolen certs happen.
- Correlate with file writes in the same directory for staging behavior.

---

## False Positives
- Third-party updaters staging binaries outside system dirs
- Portable apps run from Downloads or removable media
- IT tools/scripts using system-like names for compatibility

Mitigation: Maintain allowlists for trusted updaters/tools; refine by publisher, hash, and known paths.

---

## Recommended Response Actions
1. Determine if execution is sanctioned; if not, terminate the process.
2. Quarantine the binary and compute hashes; check reputation/intel.
3. Review parent lineage, command line, and file origin (download/share/USB).
4. Check for related Yurei activity: VSS deletion, log wiping, CIM/WMI, mass encryption, `.Yurei` files, `_README_Yurei.txt`, SMB/USB propagation.
5. Isolate host if malicious; rotate credentials and review admin groups.
6. Hunt for persistence (Run keys, Scheduled Tasks, Services, WMI subs). Preserve forensics (memory, prefetch, AmCache, shimcache, $MFT).

---

## References
- [MITRE ATT&CK: T1036.003 – Masquerading: Rename System Utilities](https://attack.mitre.org/techniques/T1036/003/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                        |
|---------|------------|-------------------|------------------------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Detection | Hunt query for suspicious process execution with system file masquerading    |
