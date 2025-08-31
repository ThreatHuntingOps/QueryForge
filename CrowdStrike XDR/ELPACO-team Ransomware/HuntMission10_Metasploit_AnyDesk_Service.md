# Correlate Metasploit Loader with AnyDesk Drop and Service Installation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 96
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MetasploitAnyDeskService
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Metasploit post-exploitation activity and attacker remote access setup. It identifies when a Metasploit loader (e.g., `HAHLGiDDb.exe`) drops `AnyDesk.exe` in the Atlassian Confluence program directory and then installs it as a service, as evidenced by the creation of AnyDesk configuration files in the system profile. This pattern is strongly associated with attackers establishing persistent remote access via legitimate remote administration tools following successful exploitation.

Detected behaviors include:

- Creation of `AnyDesk.exe` in `C:\Program Files\Atlassian\Confluence\`
- Creation of AnyDesk configuration files (e.g., `user.conf`, `ad.trace`, `system.conf`, `service.conf`) in `C:\Windows\SysWOW64\config\systemprofile\AppData\Roaming\AnyDesk\`
- Correlation of these events by process context, indicating automated loader, remote access tool deployment, and service installation

Such activity is a strong indicator of attacker remote access setup and persistence following exploitation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence         | T1133       | —            | External Remote Services                      |
| TA0004 - Privilege Escalation| T1543       | 003          | Create or Modify System Process: Windows Service |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies when `AnyDesk.exe` is dropped in the Confluence directory and is closely followed by the creation of AnyDesk configuration files in the system profile, indicating service installation and persistence.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: AnyDesk.exe dropped in Confluence directory    
#event_simpleName=FileCreate    
| FileName="AnyDesk.exe"    
| FilePath=/C:\\Program Files\\Atlassian\\Confluence\\AnyDesk\.exe/i    
| join(    
  {    
    // Inner query: AnyDesk config file creation in systemprofile    
    #event_simpleName=FileCreate    
    | FilePath=/C:\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\Roaming\\AnyDesk\\(user\.conf|ad\.trace|system\.conf|service\.conf)/i    
  }    
  , field=TargetProcessId // FileCreate's TargetProcessId    
  , key=ContextProcessId  // FileCreate's ContextProcessId    
  , include=[FilePath, FileName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FilePath, FileName]))
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | FileCreate         | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and write files as the NetworkService user and to the Confluence program directory and system profile.
- **Required Artifacts:** File creation logs, process context correlation.

---

## Considerations

- Validate the context of the process and file creation to reduce false positives.
- Confirm that the AnyDesk deployment and service installation are not part of legitimate administrative or support activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or support staff legitimately deploy AnyDesk and install it as a service for remote support in the Confluence directory.
- Internal scripts or monitoring tools use similar patterns for updates or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious AnyDesk deployment and service installation.
3. Review all processes associated with the loader and AnyDesk for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1133 – External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK: T1543.003 – Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-23 | Initial Detection | Created hunt query to detect AnyDesk drop and service installation by Metasploit loader |
