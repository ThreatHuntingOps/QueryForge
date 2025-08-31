# Correlation of wscript.exe with Unusual Network Connections and File Drops (Lumma C2 Activity)

## Metadata
**ID:** HuntQuery-CrowdStrike-LummaStealer-C2-PayloadDrop  
**OS:** WindowsEndpoint, WindowsServer  
**FP Rate:** Medium  

---

## ATT&CK Tags

| Tactic                | Technique | Subtechnique | Technique Name                                           |
|----------------------|-----------|---------------|----------------------------------------------------------|
| TA0011 - Command and Control | T1071     | 001           | Application Layer Protocol: Web Protocols                 |
| TA0005 - Defense Evasion     | T1055     | -             | Process Injection                                         |
| TA0010 - Exfiltration        | T1105     | -             | Ingress Tool Transfer                                     |

---

## Utilized Data Sources

| Log Provider | Event ID | Event Name        | ATT&CK Data Source   | ATT&CK Data Component      |
|--------------|----------|-------------------|-----------------------|-----------------------------|
| Falcon       | N/A      | NetworkConnect     | Network Traffic       | Network Connection          |
| Falcon       | N/A      | FileWritten        | File                  | File Creation               |

---

## Technical description of the attack
Lumma Stealer and similar infostealers often use `wscript.exe` to initiate C2 communications or stage additional payloads post-compromise. These activities typically involve `wscript.exe` creating outbound connections to external IPs/domains and writing executable payloads (e.g., `.exe`, `.dll`, `.tmp`) into temporary or roaming directories. This pattern is often observed during payload delivery and lateral movement stages.

---

## Permission required to execute the technique
User

---

## Detection description
This detection surfaces instances where `wscript.exe` initiates outbound network connections to public IPs or writes executable content into temp or roaming directories. These behaviors are correlated to identify potential malicious beaconing or dropper activity.

---

## Considerations
Consider incorporating `ParentProcessName`, `ChildProcessId`, `SHA256HashData`, and `CommandLine` for deeper visibility. This rule is most effective when correlated with DNS resolution or process injection behavior observed shortly after file creation.

---

## False Positives
Software installers or scripts that fetch updates or files from the internet and store them in temporary directories may trigger this alert. Validate destination IP reputation and file hash before triaging.

---

## Suggested Response Actions
- Retrieve and analyze the dropped file.
- Investigate DNS and IP metadata for known indicators of compromise.
- Monitor for follow-on process injection or persistence mechanisms.
- Isolate the host if active C2 is confirmed.
- Scan environment for similar behavior using process lineage and hash reuse.

---

## References
* [MITRE ATT&CK - T1105](https://attack.mitre.org/techniques/T1105/)
* [MITRE ATT&CK - T1055](https://attack.mitre.org/techniques/T1055/)
* [MITRE ATT&CK - T1071.001](https://attack.mitre.org/techniques/T1071/001/)
* [Threat actors using fake Chrome updates to deliver Lumma Stealer](https://security.microsoft.com/threatanalytics3/4aa69db9-9f04-46ca-b07f-c67f7105f61d/analystreport?tid=2ff60116-7431-425d-b5af-077d7791bda4&si_retry=1)

---

## Detection

**Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=NetworkConnect OR event_simpleName=FileWritten
| InitiatingProcessFileName=wscript.exe
| (RemoteAddress != "192.168.*.*" AND RemoteAddress != "10.*.*.*" AND RemoteAddress != "127.0.0.1")
| (FilePath=*\\AppData\\Local\\Temp\\* OR FilePath=*\\Users\\*\\AppData\\Roaming\\*)
| (FileName=*.exe OR FileName=*.dll OR FileName=*.tmp)
```

---
## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2025-04-13| Initial Detection | Created hunt query to detect Lumma C2 communication and payload staging via wscript.exe.|
