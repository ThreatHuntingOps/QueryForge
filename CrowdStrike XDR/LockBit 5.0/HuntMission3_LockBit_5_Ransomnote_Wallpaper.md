# Hunting for LockBit 5.0 Ransom Note Creation and Desktop Modification

## Severity or Impact of the Detected Behavior
- **Risk Score:** 88  
- **Severity:** High  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-RansomNote-DesktopChange  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low (excludes common system processes and legitimate registry paths)  

---

## Hunt Analytics

This hunt surfaces **LockBit 5.0 post-encryption impact behaviors** involving **ransom note deployment** and **desktop modifications**.  

Detected behaviors include:  
- **File creation of ransom notes** with common LockBit patterns:
  - `ReadMeForDecrypt.txt`  
  - Filenames containing `decrypt`, `ransom`, `readme`, or `lockbit`  
- **Registry modifications for desktop wallpaper changes** under Control Panel/Wallpaper keys.  
- **Filtering exclusions** to avoid noise:
  - Excludes benign processes such as `explorer.exe`, `dwm.exe`, `winlogon.exe`, `csrss.exe`.  
  - Excludes processes from `C:\Windows\System32` and `C:\Windows\SysWOW64`.  

This query provides **direct evidence of ransomware impact** - ransomware informing the victim and visually signaling compromise.  

---

## ATT&CK Mapping

| Tactic  | Technique | Subtechnique | Technique Name                          |
|---------|-----------|--------------|-----------------------------------------|
| Impact  | T1486     | -            | Data Encrypted for Impact               |
| Impact  | T1491.001 | -            | Defacement: Internal Defacement (Wallpaper/desktop modifications) |

---

## Hunt Query Logic

- File and Registry event types are inspected.  
- Match ransom note **creation events** targeting lockbit-style ransom instructions.  
- Match registry key/value changes modifying **desktop wallpaper** to display ransom messaging.  
- Exclude legitimate processes to **minimize false positives**.  

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language 
**Platform:** CrowdStrike Falcon

```fql
// LockBit-style ransom note creation + wallpaper modification (Windows)

// Windows events only
event_platform="Win"

// FileCreate-like OR RegistrySet-like events
    (
      (#event_simpleName="AsynchronousFileCreate"
       or #event_simpleName="SynchronousFileCreate"
       or #event_simpleName="NewExecutableWritten")
       and TargetFileName=/(?i)(ReadMeForDecrypt\.txt|.*decrypt.*\.txt|.*ransom.*\.txt|.*readme.*\.txt|.*lockbit.*\.txt)$/
    )
 
// Branch-specific filters, unified in one boolean where-clause
| (
    // FILE branch: ransom note patterns in created filename
    (
      (#event_simpleName="AsynchronousFileCreate"
       or #event_simpleName="SynchronousFileCreate"
       or #event_simpleName="NewExecutableWritten")
      and TargetFileName=/(?i)(ReadMeForDecrypt\.txt|.*decrypt.*\.txt|.*ransom.*\.txt|.*readme.*\.txt|.*lockbit.*\.txt)$/
    )
    or
    // REGISTRY branch: wallpaper modification keys/values
    (
      (#event_simpleName="RegistryValueSet"
       or #event_simpleName="RegistryModification"
       or #event_simpleName="RegistryItemChange")
      and (
           RegistryKey=/\\Control Panel\\Desktop/i
        or RegistryKey=/\\Desktop\\Wallpaper/i
        or RegistryValueName="Wallpaper"
      )
    )
  )

// Exclude benign system processes (explicit != checks)
| ImageFileName!="explorer.exe"
| ImageFileName!="dwm.exe"
| ImageFileName!="winlogon.exe"
| ImageFileName!="csrss.exe"

// Exclude system directory writers by command line path
| CommandLine!=/\\Windows\\System32\\/i
| CommandLine!=/\\Windows\\SysWOW64\\/i

// Output fields
| table([@timestamp,
    ComputerName,
    UserName,
    #event_simpleName,
    TargetFileName,
    FilePath,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    ImageFileName,
    CommandLine,
    ImageFilePath,
    aid])
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component     |
|----------------|------------|--------------------|---------------------------|
| Falcon         | xdr_data   | File               | File Creation             |
| Falcon         | xdr_data   | Registry           | Registry Key Modification |

---

## Execution Requirements  
- **Required Permissions:** File creation + Registry modification telemetry enabled.  
- **Required Artifacts:** Capture of full file and registry context.  

---

## Considerations  
- Ransom note files are strongly indicative of active ransomware.  
- Wallpaper registry modifications are a deliberate adversary action and **sidestep normal system processes**.  
- Recommended to correlate with file encryption and service termination detections for full kill chain coverage.  

---

## False Positives  
- Rare. Some admin scripts may change wallpapers, but ransom note naming patterns (`lockbit`, `decrypt`, `ransom`, `readme`) are highly specific.  
- The exclusions (`explorer.exe`, `winlogon.exe`, etc.) remove the majority of legitimate wallpaper changes.  

---

## Recommended Response Actions  
1. Investigate the host for evidence of confirmed ransomware impact.  
2. Identify ransom notes and collect forensic copies.  
3. Review modified registry settings to restore normal desktop appearance.  
4. Isolate and remediate the encrypting process.  
5. Begin enterprise ransomware response: backups, forensic containment, and communication.  

---

## References  
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  
- [MITRE ATT&CK: T1491.001 – Internal Defacement: Wallpaper](https://attack.mitre.org/techniques/T1491/001/)  

---

## Version History  

| Version | Date       | Impact                             | Notes                                             |
|---------|------------|------------------------------------|---------------------------------------------------|
| 1.0     | 2025-10-07 | Initial Release of Hunt Detection  | Added ransom note file + wallpaper mod hunting.   |
