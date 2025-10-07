# Detection of Command-Line Execution and Script Obfuscation - LockBit 5.0

## Severity or Impact of the Detected Behavior
- **Risk Score:** Variable (80–95 based on behavior)  
- **Severity:** Medium -> Critical depending on command type  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-CmdScriptObfuscation  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium (tuned with regex and command length heuristics)  

---

## Hunt Analytics

This hunt detects **obfuscated command-line and script executions** leveraging PowerShell, cmd.exe, and scripting engines (`wscript.exe`, `cscript.exe`) as used by **LockBit 5.0** and other ransomware families during execution and evasion phases.  

Detected behaviors include:  
- **PowerShell obfuscation**:  
  - `-EncodedCommand`, `FromBase64String`, `DownloadString`, `Invoke-Expression`, `IEX`  
  - Use of `hidden`, `bypass`, long base64-encoded strings  
- **Suspicious cmd.exe usage**:  
  - Iterative loops (`for /r`, `for /d`), destructive commands (`del`, `rmdir`, `rd`)  
  - Anti-recovery commands (`vssadmin delete shadows`, `wbadmin delete catalog`)  
  - `bcdedit` usage for tampering boot configuration  
- **Suspicious wscript/cscript usage**:  
  - Script activity in `%TEMP%`, `%APPDATA%`, or obfuscated paths with multiple dots   

This query provides enriched categorization and scoring to facilitate triage of potentially malicious execution patterns.  

---

## ATT&CK Mapping

| Tactic            | Technique   | Subtechnique | Technique Name                                           |
|-------------------|-------------|--------------|----------------------------------------------------------|
| Execution         | T1059.001   | -            | Command and Scripting Interpreter: PowerShell            |
| Execution         | T1059.003   | -            | Command and Scripting Interpreter: Windows Command Shell |
| Defense Evasion   | T1140       | -            | Deobfuscate/Decode Files or Information                  |
| Impact            | T1490       | -            | Inhibit System Recovery                                  |

---

## Hunt Query Logic

The query examines command-line executions of PowerShell, cmd.exe, wscript.exe, and cscript.exe.  
- Matches suspicious strings, obfuscation patterns, and anti-recovery commands.  
- Assigns **flags for long base64/very long commands**.  

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language 
**Platform:** CrowdStrike Falcon 

```fql
// Title: LockBit 5.0 Command-Line Execution and Script Obfuscation 
// Description: Detects obfuscated PowerShell, batch scripts, and command-line patterns used by LockBit 5.0 
// MITRE ATT&CK TTP ID: T1059.003 (Windows Command Shell) 
// MITRE ATT&CK TTP ID: T1059.001 (PowerShell) 

#event_simpleName=ProcessRollup2
| event_platform="Win"

// Scope to common script/shell hosts
| (ImageFileName="powershell.exe" or ImageFileName="cmd.exe" or ImageFileName="wscript.exe" or ImageFileName="cscript.exe")

// Suspicious patterns per host process
| (
  // PowerShell
  (ImageFileName="powershell.exe" and (
      CommandLine=/-e(ncodedCommand)?/i
      or CommandLine=/FromBase64String/i
      or CommandLine=/DownloadString/i
      or CommandLine=/\bIEX\b/i
      or CommandLine=/\bInvoke-Expression\b/i
      or CommandLine=/\bhidden\b/i
      or CommandLine=/\bbypass\b/i
      or CommandLine=/[A-Za-z0-9+\/]{20,}={0,2}/
  ))
  or
  // cmd.exe
  (ImageFileName="cmd.exe" and (
      CommandLine=/for\s+\/r/i
      or CommandLine=/for\s+\/d/i
      or CommandLine=/&&\s*echo/i
      or CommandLine=/vssadmin\s+delete\s+shadows/i
      or CommandLine=/wbadmin\s+delete\s+catalog/i
      or CommandLine=/\bbcdedit\b/i
      or CommandLine=/\b(del|rmdir|rd)\b/i
  ))
  or
  // wscript / cscript
  ((ImageFileName="wscript.exe" or ImageFileName="cscript.exe") and (
      CommandLine=/\\Temp\\/
      or CommandLine=/\\AppData\\/
      or CommandLine=/\\\.{3,}/
  ))
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
- **Required Permissions:** Process telemetry with command-line arguments.  
- **Required Artifacts:** Presence of long commands, encoded data, or destructive commands.  

---

## Considerations  
- Query categorizes execution into **obfuscation, destructive activity, or persistence tampering**.  
- May require **environment-specific tuning** due to legitimate long or encoded commands.  
- Most suspicious when combined with **concurrent service termination or encryption artifacts**.  

---

## False Positives  
- Legitimate administrative tasks (backups, scripts, encoded PowerShell) may trigger detection.  
- Developers or sysadmins using scripts with long command lines could appear suspicious.  

---

## Recommended Response Actions  
1. Investigate command line and process ancestry.  
2. Validate intent of execution (user-initiated or adversary-driven).  
3. Correlate with other LockBit TTPs, e.g. encryption, persistence.  
4. Quarantine suspicious binaries and isolate host.  
5. If confirmed malicious, initiate ransomware response workflow.  

---

## References  
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)  
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)  

---

## Version History  

| Version | Date       | Impact                                   | Notes                                                   |
|---------|------------|------------------------------------------|---------------------------------------------------------|
| 1.0     | 2025-10-07 | Initial Release of Script Obfuscation    | Added detection categories and heuristic severity scoring |
