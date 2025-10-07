# Detection of Event Log Clearing and Anti-Forensic Activities - LockBit 5.0

## Severity or Impact of the Detected Behavior
- **Risk Score:** 94  
- **Severity:** Critical  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-EventLogClearing  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low (log clearing is a rare and high-risk activity)  

---

## Hunt Analytics

This hunt query detects **event log manipulation and clearing behaviors** associated with **LockBit 5.0** ransomware and related adversaries.  
Ransomware actors frequently attempt to **erase forensic evidence and defense telemetry** following encryption activities.  

Detected behaviors include:  
- **Event log clearing via `wevtutil.exe`** (`clear-log`, `cl`, `/e:false`).  
- **PowerShell-based log manipulation** (`Clear-EventLog`, `Remove-EventLog`, `System.Diagnostics.EventLog`, `Limit-EventLog`).  
- **Registry modifications** disabling or shrinking log storage (`Enabled=0`, `MaxSize=0`) under EventLog service keys.  
- **Direct deletion of event log files** (`.evtx`) using `del.exe`, `erase.exe`, or `cmd.exe`.  
- **Focus on common log types**: `Security`, `System`, `Application`, `Setup`, `ForwardedEvents`, `Microsoft-Windows-*`.  

This activity is a strong indicator of **anti-forensic behavior** that typically precedes or follows file encryption.  

---

## ATT&CK Mapping

| Tactic           | Technique   | Subtechnique | Technique Name                                  |
|------------------|-------------|--------------|------------------------------------------------|
| Defense Evasion  | T1070.001   | -            | Indicator Removal on Host: Clear Windows Event Logs |
| Defense Evasion  | T1562.002   | -           | Impair Defenses: Disable Windows Event Logging |

---

## Hunt Query Logic

The query inspects both process execution and registry modifications:  
- Detects log clearing via `wevtutil`, PowerShell scripts, and destructive commands against `.evtx` files.  
- Detects registry edits disabling logging services or event channels.  
- Focuses on **security/audit-related logs** commonly targeted by attackers.  
- Derives count of logs affected via regex extraction (`log_types_cleared`).  

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language
**Platform:** CrowdStrike Falcon 

```fql
// Title: LockBit 5.0 Event Log Clearing and Anti-Forensic Activities 
// Description: Detects event log manipulation and clearing activities used by LockBit 5.0 to hide attack footprints post-encryption 
// MITRE ATT&CK TTP ID: T1070.001 (Indicator Removal on Host: Clear Windows Event Logs) 
// MITRE ATT&CK TTP ID: T1562.002 (Impair Defenses: Disable Windows Event Logging) 

// Limit to Windows and relevant event types
event_platform="Win"
| (
    #event_simpleName="ProcessRollup2"
    or #event_simpleName="RegistryValueSet"
    or #event_simpleName="RegistryModification"
    or #event_simpleName="RegistryItemChange"
  )

// Process- and Registry-based behaviors
| (
    // wevtutil-based clearing
    (ImageFileName="wevtutil.exe" and (
        CommandLine=/clear-log/i
        or CommandLine=/\bcl\b/i
        or CommandLine=/\/e:false/i
    ))
    or
    // PowerShell event log manipulation
    (ImageFileName="powershell.exe" and (
        CommandLine=/Clear-EventLog/i
        or CommandLine=/Remove-EventLog/i
        or CommandLine=/System\.Diagnostics\.EventLog/i
        or CommandLine=/Limit-EventLog/i
    ))
    or
    // Registry changes impacting logging
    ( (
        RegistryKey=/\\CurrentControlSet\\Services\\EventLog/i
        or RegistryKey=/\\Winevt\\Channels/i
        or (RegistryValueName="Enabled" and RegistryValueData="0")
        or (RegistryValueName="MaxSize" and RegistryValueData="0")
    ))
    or
    // Direct deletion of .evtx files
    ((ImageFileName="del.exe" or ImageFileName="erase.exe" or ImageFileName="cmd.exe") and (
        CommandLine=/\.evtx/i
        or CommandLine=/\\System32\\winevt\\Logs\\/i
    ))
)

// Target common Windows logs (either in command line or in registry path)
| (
    CommandLine=/(?i)(security|system|application|setup|forwarded|microsoft-windows-)/
    or RegistryKey=/(?i)(security|system|application|setup)/
)

// Output fields (Process + Registry)
| select(
    @timestamp,
    ComputerName,
    UserName,
    #event_simpleName,
    ImageFileName,
    CommandLine,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    ParentImageFileName,
    ParentCommandLine,
    aid
)

// Sort newest first
| sort(field=@timestamp, order=desc, limit=1000)
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source   | ATT&CK Data Component   |
|----------------|------------|----------------------|-------------------------|
| Falcon            | xdr_data   | Process              | Process Creation        |
| Falcon         | xdr_data   | Registry             | Registry Key Modification |

---

## Execution Requirements  
- **Required Permissions:** Process + registry telemetry collection must be active.  
- **Required Artifacts:** Capture of command lines, registry edits, and file path context.  

---

## Considerations  
- Log clearing is a **high-confidence signal** of malicious activity.  
- Should always trigger **priority triage** especially when correlated with **encryption events or service stops**.  

---

## False Positives  
- Extremely rare. Admins occasionally clear event logs during maintenance, but registry disabling or direct `.evtx` deletion is highly suspicious.  

---

## Recommended Response Actions  
1. Investigate the process that attempted log clearing.  
2. Correlate activity with ransomware-related detections (encryption, service disablement).  
3. Collect and preserve surviving event logs for forensic reconstruction.  
4. Isolate endpoint and begin ransomware incident response.  
5. Re-enable and validate logging mechanisms across the environment.  

---

## References  
- [MITRE ATT&CK: T1070.001 – Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)  
- [MITRE ATT&CK: T1562.002 – Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)  

---

## Version History  

| Version | Date       | Impact                                      | Notes                                          |
|---------|------------|---------------------------------------------|------------------------------------------------|
| 1.0     | 2025-10-07 | Initial Release - Event Log Clearing Hunt   | Detects registry, process, and direct file deletions |
