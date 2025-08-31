# Correlate AnyDesk Session with Suspicious DLL Drop (spider.dll)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 92
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnyDeskSpiderDLL
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors associated with lateral movement or further persistence via remote access tools. It identifies when a DLL (e.g., `spider.dll` or `spider_32.dll`) is dropped in a user's Desktop folder by `explorer.exe` after an AnyDesk session. This pattern is strongly associated with attackers transferring malicious DLLs via remote access sessions for further exploitation or persistence.

Detected behaviors include:

- Creation of a DLL file (`spider.dll` or `spider_32.dll`) in `C:\Users\<username>\Desktop\Attacker\share\`
- The file is created by `explorer.exe` after an AnyDesk session is active on the system
- Correlation of these events by process context, indicating file transfer via remote access

Such activity is a strong indicator of lateral movement, persistence, or further exploitation following remote access.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021       | —            | Remote Services                               |
| TA0003 - Persistence         | T1547       | —            | Boot or Logon Autostart Execution             |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies when a DLL (e.g., `spider.dll` or `spider_32.dll`) is dropped in a user's Desktop folder by `explorer.exe` after an AnyDesk session. This sequence is a strong indicator of file transfer and possible lateral movement or persistence.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: DLL file creation on Desktop by explorer.exe    
#event_simpleName=FileCreate    
| FileName=/spider(_32)?\.dll/i    
| FilePath=/C:\\Users\\[^\\]+\\Desktop\\Attacker\\share\\spider(_32)?\.dll/i    
| join(    
  {    
    // Inner query: AnyDesk process running on the system    
    #event_simpleName=ProcessRollup2    
    | FileName="AnyDesk.exe"    
  }    
  , field=TargetProcessId // FileCreate's TargetProcessId    
  , key=ContextProcessId  // AnyDesk.exe's ContextProcessId    
  , include=[FileName, FilePath]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FilePath, FileName])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | FileCreate         | File                | File Creation          |
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and transfer files via AnyDesk remote session.
- **Required Artifacts:** File creation logs, process creation logs, process context correlation.

---

## Considerations

- Validate the context of the DLL drop and AnyDesk session to reduce false positives.
- Confirm that the DLL transfer is not part of legitimate administrative or support activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately transfer DLLs via AnyDesk for troubleshooting or updates.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network.
2. Investigate the source and intent of the suspicious DLL transfer and AnyDesk session.
3. Review all processes associated with explorer.exe and AnyDesk for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1021 – Remote Services](https://attack.mitre.org/techniques/T1021/)
- [MITRE ATT&CK: T1547 – Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-26 | Initial Detection | Created hunt query to detect AnyDesk session and suspicious DLL drop on Desktop |
