# Detection of Unique Process Characteristics and Mutex Creation - LockBit 5.0

## Severity or Impact of the Detected Behavior
- **Risk Score:** 86  
- **Severity:** High  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-Process-Mutex  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium (filters exclude benign processes but tuning may be needed)  

---

## Hunt Analytics

This hunt identifies **unique process execution patterns, environment reconnaissance, and mutex creation** behaviors associated with **LockBit 5.0 ransomware**.  
LockBit performs pre-encryption discovery and system situational awareness to tailor execution and restrict infections to targeted regions.  

Detected behaviors include:  
- **Geolocation/System checks**: Command lines referencing locale, language, timezone, and related APIs (`GetLocaleInfo`, `GetTimeZoneInformation`, `GetSystemDefaultLCID`).  
- **System reconnaissance**: Enumeration commands like `hostname`, `whoami`, `systeminfo`, `tasklist`, `net view`, `net user`.  
- **Mutex activity**: Creation or opening of mutexes (`CreateMutex`, `OpenMutex`) as infection tracking mechanisms.  
- **Custom Global mutex patterns**: Global names with 8–16 randomized characters.  
- **Execution from user-writable directories**: Processes from `%TEMP%`, `%AppData%`, `Downloads`, or `Users/Public`.  

These indicators combined are highly indicative of LockBit’s execution patterns.  

---

## ATT&CK Mapping

| Tactic               | Technique   | Subtechnique | Technique Name               |
|----------------------|-------------|--------------|------------------------------|
| Discovery            | T1057       | -            | Process Discovery            |
| Discovery            | T1082       | -            | System Information Discovery |
| Defense Evasion      | T1070.004   | -            | File Deletion (mutex indicator cleanup possible) |

---

## Hunt Query Logic

1. Detects suspicious command-line indicators for reconnaissance.  
2. Matches creation or opening of mutex objects.  
3. Enforces presence of processes running from user-controlled directories.  
4. Excludes common benign system processes.  
5. Requires at least one reconnaissance command match (`recon_commands >= 1`).  

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language  
**Platform:** CrowdStrike Falcon  

```fql
// Title: LockBit 5.0 Unique Process Characteristics and Mutex Detection 
// Description: Detects LockBit 5.0's unique process execution patterns, geolocation checks, and mutex creation for infection tracking 
// MITRE ATT&CK TTP ID: T1057 (Process Discovery) 
// MITRE ATT&CK TTP ID: T1082 (System Information Discovery) 

// Windows process events only
#event_simpleName=ProcessRollup2
| event_platform="Win"

// Geolocation/system checks + recon + mutex indicators on command line
| (
    // Geolocation and system checks
    CommandLine=/(?i)(locale|language|timezone|country)/
    or CommandLine=/GetLocaleInfo/i
    or CommandLine=/GetTimeZoneInformation/i
    or CommandLine=/GetSystemDefaultLCID/i

    // System reconnaissance patterns
    or CommandLine=/(?i)(hostname|whoami|systeminfo|tasklist|net\s+view|net\s+user)/

    // Mutex and synchronization objects
    or CommandLine=/CreateMutex/i
    or CommandLine=/OpenMutex/i
    or CommandLine=/Global[A-Za-z0-9]{8,16}/
)

// Exclusions for likely-legit parents and common system app paths
| not (ParentImageFileName="explorer.exe" or ParentImageFileName="svchost.exe" or ParentImageFileName="winlogon.exe")
| CommandLine!=/\\Windows\\System32\\/
| CommandLine!=/\\Program Files\\/

// Processes spawned from temp/user-writable paths (parent path)
| (
    ParentCommandLine=/\\Temp\\/
    or ParentCommandLine=/\\AppData\\/
    or ParentCommandLine=/\\Downloads\\/
    or ParentCommandLine=/\\Users\\Public\\/
)

// Recon presence gate
| (
    CommandLine=/(?i)(hostname|whoami|systeminfo|tasklist|net)/
)

// Output fields
| select(
    @timestamp,
    ComputerName,
    UserName,
    ImageFileName,
    CommandLine,
    ParentImageFileName,
    ParentCommandLine,
    SHA256HashData,
    aid,
    #event_simpleName
)

// Sort by newest
| sort(field=@timestamp, order=desc, limit=1000)
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Falcon       | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements  
- **Required Permissions:** Command-line process telemetry enabled.  
- **Required Artifacts:** Process image path, command-line content, parent-child execution chain.  

---

## Considerations  
- May overlap with legitimate administrative tasks using recon commands, though combined with mutex creation and execution from non-standard directories makes it highly suspicious.  
- Should be **correlated with file encryption and ransom note activity** to confirm LockBit infection.  

---

## False Positives  
- Possible from IT scripts/tools that use reconnaissance commands, but rare to see alongside mutex creation and execution from `%TEMP%` or `%AppData%`.  

---

## Recommended Response Actions  
1. Investigate suspicious processes for potential malware injection or mutex generation.  
2. Collect process binary and analyze SHA256 hash.  
3. Review reconnaissance command outputs for adversary information gathering.  
4. Correlate activity with subsequent encryption or ransom note creation.  
5. Isolate and rebuild affected systems as required.  

---

## References  
- [MITRE ATT&CK: T1057 – Process Discovery](https://attack.mitre.org/techniques/T1057/)  
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)  

---

## Version History  

| Version | Date       | Impact                              | Notes                                                 |
|---------|------------|-------------------------------------|-------------------------------------------------------|
| 1.0     | 2025-10-07 | Initial Release – Process & Mutex   | Detection of unique LockBit recon and mutex patterns. |
