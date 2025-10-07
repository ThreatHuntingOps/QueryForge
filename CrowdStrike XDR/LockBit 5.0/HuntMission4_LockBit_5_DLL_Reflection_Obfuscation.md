# Detection of DLL Reflection and Advanced Obfuscation - LockBit 5.0

## Severity or Impact of the Detected Behavior
- **Risk Score:** 87  
- **Severity:** High  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-DLL-Reflection-Obfuscation  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium (requires tuning for environment-specific legitimate reflection usage)  

---

## Hunt Analytics

This hunt detects **DLL reflection, API hashing, and advanced obfuscation techniques** commonly employed by **LockBit 5.0** to evade detection and execute malicious payloads in memory.  

Detected behaviors include:  
- **Reflective DLL loading** via `Assembly.Load`, `System.Reflection`, `GetMethod`, `Invoke`.  
- **Memory manipulation APIs** such as `VirtualAlloc`, `GetProcAddress`, `LoadLibrary`, `CreateThread`.  
- **Base64-encoded payloads** in command lines (50+ character sequences).  
- **Suspicious hexadecimal constants** (e.g., `0x12345678`) indicative of API hashing or shellcode.  
- **Exclusions** for common benign processes (`svchost.exe`, `explorer.exe`, `dwm.exe`) and system directories (`System32`, `Program Files`).  

These techniques allow adversaries to **bypass static detection**, execute code without touching disk, and **inject into legitimate processes**.  

---

## ATT&CK Mapping

| Tactic           | Technique | Subtechnique | Technique Name                                  |
|------------------|-----------|--------------|------------------------------------------------|
| Defense Evasion  | T1027     |              | Obfuscated Files or Information                |
| Defense Evasion  | T1055     | T1055.001    | Process Injection: Dynamic-link Library Injection |

---

## Hunt Query Logic

This query identifies suspicious process command lines containing:  
1. **Reflection and dynamic invocation** keywords (`Assembly.Load`, `System.Reflection`, `GetMethod`, `Invoke`).  
2. **Memory manipulation APIs** (`VirtualAlloc`, `GetProcAddress`, `LoadLibrary`, `CreateThread`).  
3. **Base64-encoded content** (50+ character alphanumeric sequences with optional padding).  
4. **Hexadecimal constants** (e.g., `0xABCDEF12`) often used in API hashing or shellcode.  

Exclusions reduce noise from legitimate system processes and trusted software directories.  

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language 
**Platform:** CrowdStrike Falcon  

```fql
// Title: LockBit 5.0 DLL Reflection and Advanced Obfuscation Detection 
// Description: Detects DLL reflection, API hashing, and obfuscation techniques characteristic of LockBit 5.0's stealth mechanisms 
// MITRE ATT&CK TTPs: T1027 (Obfuscated Files or Information), T1055.001 (Process Injection: DLL Injection) 

// LockBit 5.0 DLL reflection / obfuscation indicators in process command lines (Windows)

// Process events (ProcessRollup2) on Windows
#event_simpleName=ProcessRollup2
| event_platform="Win"

// Obfuscation / reflection indicators (command-line substrings or regex)
| (
    CommandLine=/Assembly\.Load/i
    or CommandLine=/System\.Reflection/i
    or CommandLine=/\bGetMethod\b/i
    or CommandLine=/\bInvoke\b/i
    or CommandLine=/\bVirtualAlloc\b/i
    or CommandLine=/\bGetProcAddress\b/i
    or CommandLine=/\bLoadLibrary\b/i
    or CommandLine=/\bCreateThread\b/i
    // Base64-like long blob
    or CommandLine=/[A-Za-z0-9+\/]{50,}={0,2}/
    // Hex constants (e.g., function hashes, flags)
    or CommandLine=/0x[0-9A-Fa-f]{8}/
  )

// Exclusions: benign parent images and common system install paths
| ParentImageFileName!="svchost.exe"
| ParentImageFileName!="explorer.exe"
| ParentImageFileName!="dwm.exe"
| CommandLine!=/\\Windows\\System32\\/i
| CommandLine!=/\\Program Files( \(x86\))?\\/i

// Output fields analogous to XQL
| select(
    @timestamp,
    ComputerName,
    UserName,
    ImageFileName,
    CommandLine,
    ParentImageFileName,
    SHA256HashData,
    aid,
    #event_simpleName
  )

// Sort newest first
| sort(field=@timestamp, order=desc, limit=1000)
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Falcon         | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements  
- **Required Permissions:** Process execution telemetry with full command-line capture.  
- **Required Artifacts:** Command-line arguments, process image paths, parent process context.  

---

## Considerations  
- **Reflection and dynamic invocation** are legitimate in .NET applications but are heavily abused by malware.  
- **Base64 regex** may trigger on legitimate encoded parameters (e.g., AppX package names, tokens). Tune exclusions as needed.  
- **Hexadecimal constants** are common in shellcode loaders and API hashing routines.  
- Correlate with **file encryption, service termination, or persistence** for full attack chain validation.  

---

## False Positives  
- **Medium likelihood**: Legitimate .NET applications, PowerShell scripts, and admin tools may use reflection or base64 encoding.  
- **Mitigation**: Add exclusions for trusted software paths (`Program Files`, `System32`) and known benign processes.  
- Validate alerts by inspecting parent process, user context, and subsequent activity.  

---

## Recommended Response Actions  
1. Investigate the process and command line for malicious intent.  
2. Analyze parent process and execution chain for signs of compromise.  
3. Collect and analyze the binary (SHA256 hash) for malware indicators.  
4. Search for related activity: file encryption, service stops, persistence mechanisms.  
5. Isolate affected endpoints if malicious activity is confirmed.  

---

## References  
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)  
- [MITRE ATT&CK: T1055.001 – Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)  

---

## Version History  

| Version | Date       | Impact                                | Notes                                          |
|---------|------------|---------------------------------------|------------------------------------------------|
| 1.0     | 2025-10-07 | Initial Release of Obfuscation Hunt   | Detects DLL reflection and obfuscation techniques |
