# Detection of Credential Access with LSASS Access and Sensitive Registry Key Queries

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-CredentialAccess-LSASS-Registry
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt extends credential access detection by adding visibility into LSASS memory access (potential credential dumping) and monitoring for sensitive registry key queries. It covers DonPAPI, Impacket, Certipy, and Orpheus usage, as well as LSASS process access and registry queries commonly used by attackers for credential theft or privilege escalation. These behaviors are strong indicators of credential dumping, certificate theft, and persistence or privilege escalation attempts in enterprise environments.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                              |
|------------------------------|-------------|--------------|-------------------------------------------------------------|
| TA0006 - Credential Access   | T1555.004   | —            | Credentials from Password Stores: Windows Credential Manager |
| TA0006 - Credential Access   | T1555.003   | —            | Credentials from Password Stores: Credentials in Browsers    |
| TA0006 - Credential Access   | T1552.001   | —            | Unsecured Credentials: Credentials in Files                  |
| TA0006 - Credential Access   | T1558.004   | —            | Steal or Forge Authentication Certificates: Golden Certificate |
| TA0006 - Credential Access   | T1558.003   | —            | Steal or Forge Authentication Certificates: Steal AD CS Certificates |
| TA0006 - Credential Access   | T1558.001   | —            | Steal or Forge Kerberos Tickets: Golden Ticket               |
| TA0006 - Credential Access   | T1558.002   | —            | Steal or Forge Kerberos Tickets: Silver Ticket               |
| TA0006 - Credential Access   | T1558.003   | —            | Kerberoasting                                              |
| TA0006 - Credential Access   | T1003       | —            | Credential Dumping (LSASS access)                            |
| TA0011 - Command and Control | T1071.001   | —            | Application Layer Protocol: Web Protocols                    |

---

## Hunt Query Logic

This query identifies:

- DonPAPI or Impacket DPAPI extraction via command-line options and file creation
- PVK usage or DonPAPI/dpapi-related folder/file writes
- Certipy abuse to enumerate AD CS templates (e.g., `certipy find -ldap`)
- Orpheus tool download and execution patterns
- Parent-child relationships between shells (PowerShell, Python) and credential dump tools
- LSASS process access or memory dumps (e.g., Mimikatz usage)
- Sensitive registry key queries and value data related to credentials or hashes

These behaviors are rarely seen in legitimate administrative activity and are strong indicators of credential theft, privilege escalation, and persistence.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 OR #event_simpleName=FileCreate OR #event_simpleName=RegistryQuery OR #event_simpleName=ProcessMemoryDump // DonPAPI or dpapi.py usage 
| (FileName="donpapi" OR FileName="donpapi.py" OR CommandLine="*--GetHashes*" OR CommandLine="*-pvk*" OR CommandLine="*dpapi.py*") | (CommandLine="*--no_remoteops*" OR CommandLine="*--no_vnc*" OR CommandLine="*--no_recent*" OR CommandLine="*--no_sysadmins*") // File creation of output or PVK keys 
| (#event_simpleName=FileCreate AND (FileName ENDSWITH ".pvk" OR FilePath="*\\dpapi\\*" OR FilePath="*\\donpapi\\*")) // Certipy enumeration or exploitation 
| (FileName="certipy" OR FileName="certipy.exe" OR CommandLine="*find*" AND CommandLine="*template*" AND CommandLine="*ldap*") // Potential Orpheus or tool download behavior 
| (CommandLine="*wget*" OR CommandLine="*curl*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*git clone*" AND CommandLine="*orpheus*") 
| (#event_simpleName=FileCreate AND (FileName="orpheus.py" OR FilePath="*\\orpheus\\*")) // Process ancestry: PowerShell or Python launching credential tools 
| ((ParentBaseFileName="powershell.exe" OR ParentBaseFileName="python.exe") AND (FileName="donpapi.py" OR FileName="dpapi.py" OR FileName="certipy.py" OR FileName="orpheus.py")) // Detecting LSASS access for credential dumping 
| (#event_simpleName=ProcessRollup2 AND FileName="lsass.exe" AND (CommandLine="*dump*" OR CommandLine="*mimikatz*")) 
| (#event_simpleName=ProcessMemoryDump AND FilePath="*\\lsass.exe") // Sensitive registry key query (to detect potential credential access or privilege escalation attempts) 
| (#event_simpleName=RegistryQuery AND (KeyPath="*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*" OR KeyPath="*\\SYSTEM\\CurrentControlSet\\Services\\LSA*" OR KeyPath="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*")) 
| (RegistryValueName="*" AND RegistryValueData="*password*" OR RegistryValueData="*hash*")  
```

---

## Data Sources

| Log Provider | Event ID | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|--------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A      | FileCreate         | File                | File Creation          |
| Falcon       | N/A      | RegistryQuery      | Registry            | Registry Key/Value     |
| Falcon       | N/A      | ProcessMemoryDump  | Process             | Memory Dump            |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute credential access tools and scripts, access sensitive files, query registry, and access LSASS memory.
- **Required Artifacts:** Script execution logs, process creation events, file creation logs, registry query logs, and memory dump events.

---

## Considerations

- Investigate the source and context of credential access tool usage.
- Review command-line arguments, output files, registry queries, and memory dumps for targeted credentials or certificates.
- Correlate with authentication and network logs for unauthorized access or lateral movement.
- Examine for follow-on activity such as privilege escalation, ticket forging, or persistence.

---

## False Positives

False positives may occur if:

- Administrators are legitimately using credential access tools for recovery or migration.
- Security or compliance tools use similar automation for credential audits or registry monitoring.

---

## Recommended Response Actions

1. Investigate the initiating process and its source.
2. Analyze command-line arguments, output files, registry queries, and memory dumps for malicious indicators.
3. Review authentication and network logs for unauthorized access or credential theft.
4. Isolate affected systems if confirmed malicious.
5. Reset compromised credentials and review access policies.

---

## References

- [MITRE ATT&CK: T1555.004 – Credentials from Password Stores: Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/)
- [MITRE ATT&CK: T1555.003 – Credentials from Password Stores: Credentials in Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK: T1552.001 – Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE ATT&CK: T1558.004 – Steal or Forge Authentication Certificates: Golden Certificate](https://attack.mitre.org/techniques/T1558/004/)
- [MITRE ATT&CK: T1558.003 – Steal or Forge Authentication Certificates: Steal AD CS Certificates](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK: T1558.001 – Steal or Forge Kerberos Tickets: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
- [MITRE ATT&CK: T1558.002 – Steal or Forge Kerberos Tickets: Silver Ticket](https://attack.mitre.org/techniques/T1558/002/)
- [MITRE ATT&CK: T1558.003 – Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK: T1003 – Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-30 | Initial Detection | Created hunt query to detect credential access with LSASS access and sensitive registry key queries |
