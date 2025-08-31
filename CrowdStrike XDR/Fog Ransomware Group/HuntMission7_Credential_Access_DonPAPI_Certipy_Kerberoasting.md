# Detection of Credential Access via DPAPI Extraction, Certificate Theft, and Kerberoasting Prep

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-CredentialAccess-DonPAPI-Certipy-Kerberoasting
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects possible credential theft operations using DonPAPI, Impacket, Certipy, and Orpheus, which are tools often used to extract sensitive credentials, hashes, and certificates from Windows systems in enterprise environments. The query identifies command-line usage, file creation, and process ancestry patterns consistent with DPAPI extraction, certificate theft, and Kerberoasting preparation, as observed in recent targeted attacks and ransomware affiliate campaigns.

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

---

## Hunt Query Logic

This query identifies:

- DonPAPI or Impacket DPAPI extraction via command-line options and file creation
- PVK usage or DonPAPI/dpapi-related folder/file writes
- Certipy abuse to enumerate AD CS templates (e.g., `certipy find -ldap`)
- Orpheus tool download and execution patterns
- Parent-child relationships between shells (PowerShell, Python) and credential dump tools

These behaviors are rarely seen in legitimate administrative activity and are strong indicators of credential theft and preparation for further attacks.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 OR #event_simpleName=FileCreate OR #event_simpleName=ScriptLoad // DonPAPI or dpapi.py usage  
| (FileName="donpapi" OR FileName="donpapi.py" OR CommandLine="*--GetHashes*" OR CommandLine="*-pvk*" OR CommandLine="*dpapi.py*")  
| (CommandLine="*--no_remoteops*" OR CommandLine="*--no_vnc*" OR CommandLine="*--no_recent*" OR CommandLine="*--no_sysadmins*") // File creation of output or PVK keys  
| (#event_simpleName=FileCreate AND (FileName ENDSWITH ".pvk" OR FilePath="*\\dpapi\\*" OR FilePath="*\\donpapi\\*")) // Certipy enumeration or exploitation  
| (FileName="certipy" OR FileName="certipy.exe" OR CommandLine="*find*" AND CommandLine="*template*" AND CommandLine="*ldap*") // Potential Orpheus or tool download behavior  
| (CommandLine="*wget*" OR CommandLine="*curl*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*git clone*" AND CommandLine="*orpheus*")  
| (#event_simpleName=FileCreate AND (FileName="orpheus.py" OR FilePath="*\\orpheus\\*")) // Process ancestry: PowerShell or Python launching credential tools  
| ((ParentBaseFileName="powershell.exe" OR ParentBaseFileName="python.exe") AND (FileName="donpapi.py" OR FileName="dpapi.py" OR FileName="certipy.py" OR FileName="orpheus.py"))   
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |
| Falcon       | N/A      | FileCreate       | File                | File Creation          |
| Falcon       | N/A      | ScriptLoad       | Script              | Script Load            |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute credential access tools and scripts, and access sensitive files.
- **Required Artifacts:** Script execution logs, process creation events, file creation logs, and command-line arguments.

---

## Considerations

- Investigate the source and context of credential access tool usage.
- Review command-line arguments and output files for targeted credentials or certificates.
- Correlate with authentication and network logs for unauthorized access or lateral movement.
- Examine for follow-on activity such as privilege escalation or ticket forging.

---

## False Positives

False positives may occur if:

- Administrators are legitimately using credential access tools for recovery or migration.
- Security or compliance tools use similar automation for credential audits.

---

## Recommended Response Actions

1. Investigate the initiating process and its source.
2. Analyze command-line arguments and output files for malicious indicators.
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
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-30 | Initial Detection | Created hunt query to detect credential access via DPAPI extraction, certificate theft, and Kerberoasting prep |
