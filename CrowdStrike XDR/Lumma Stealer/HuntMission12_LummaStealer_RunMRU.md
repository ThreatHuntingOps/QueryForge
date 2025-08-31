
# Suspicious ClickFix/RunMRU Registry Modification Linked to Lumma Stealer Delivery

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RunMRU-LummaStealer
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious modifications to the Windows RunMRU registry key, which is commonly abused by malware such as Lumma Stealer for initial access, persistence, and execution of malicious payloads. The query identifies patterns associated with ClickFix commands and other suspicious command-line activity, including the use of living-off-the-land binaries (LOLBins) and obfuscated PowerShell or mshta commands. These behaviors are consistent with the delivery and execution techniques described in [Microsoft's analysis of Lumma Stealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/).

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                            |
|------------------------------|-------------|--------------|----------------------------------------------------------|
| TA0002 - Execution            | T1059       | 001, 003, 005| Command and Scripting Interpreter (PowerShell, mshta, etc)|
| TA0003 - Persistence          | T1547       | 001          | Boot or Logon Autostart Execution: Registry Run Keys      |
| TA0005 - Defense Evasion      | T1218       | 010, 011     | Signed Binary Proxy Execution (mshta, bitsadmin, etc)     |
| TA0006 - Credential Access    | T1555       | 003          | Credentials from Password Stores: Web Browsers            |
| TA0011 - Command and Control  | T1105       | —            | Ingress Tool Transfer                                     |

---

## Hunt Query Logic

This query identifies suspicious RunMRU registry modifications that may indicate the delivery or execution of infostealer malware such as Lumma Stealer. It looks for:

- Registry value sets in the RunMRU key initiated by explorer.exe
- Use of suspicious commands or LOLBins (e.g., powershell, mshta, curl, bitsadmin)
- Obfuscation or encoded payloads (e.g., base64, -e, -enc)
- Exclusion of benign MRUList updates

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)
**Platform:** CrowdStrike Falcon

```fql
// Identify ClickFix commands execution
#event_simpleName=RegistryModificationEvent
AND ActionType=RegistryValueSet
AND InitiatingProcessFileName=explorer.exe
AND RegistryKeyName:*\\CurrentVersion\\Explorer\\RunMRU*
AND (
    RegistryValueData:*✅*
    OR (
        RegistryValueData:("powershell" OR "mshta" OR "curl" OR "msiexec" OR "^")
        /* Unicode/obfuscation detection not supported, so this line is omitted */
    )
    OR (
        RegistryValueData:*mshta*
        AND NOT RegistryValueName=MRUList
        AND NOT (RegistryValueData="mshta.exe\\1" OR RegistryValueData="mshta\\1")
    )
    OR (
        RegistryValueData:("bitsadmin" OR "forfiles" OR "ProxyCommand=")
        AND NOT RegistryValueName=MRUList
    )
    OR (
        (RegistryValueData:/^cmd.*/ OR RegistryValueData:/^powershell.*/)
        AND (
            RegistryValueData:("-W Hidden " OR "-eC " OR "curl" OR "E:jscript" OR "ssh" OR "Invoke-Expression" OR "UtcNow" OR "Floor" OR "DownloadString" OR "DownloadFile" OR "FromBase64String" OR "System.IO.Compression" OR "System.IO.MemoryStream" OR "iex" OR "Invoke-WebRequest" OR "iwr" OR "Get-ADDomainController" OR "InstallProduct" OR "-w h" OR "-X POST" OR "Invoke-RestMethod" OR "-NoP -W" OR ".InVOKe" OR "-useb" OR "irm " OR "^" OR "[char]" OR "[scriptblock]" OR "-UserAgent" OR "UseBasicParsing" OR ".Content" OR "*-e " OR "*-ec " OR "*-enc " OR "*-encoded " OR "*base64*" OR "*==*")
        )
    )
)
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|--------------------------|---------------------|------------------------|
| Falcon       | RegistryModificationEvent | Registry            | Registry Key Modification |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to modify registry RunMRU keys.
- **Required Artifacts:** Registry event logs, command-line usage, process ancestry.

---

## Considerations

- Investigate the full command line and parent process for context.
- Validate if any encoded or obfuscated payloads are present.
- Review for follow-on process creation or network activity.
- Correlate with threat intelligence on Lumma Stealer and related IOCs.

---

## False Positives

False positives may occur if:

- Users legitimately use RunMRU for automation or scripting.
- Internal tools or scripts update RunMRU with benign commands.
- Security or IT staff perform legitimate registry modifications.

---

## Recommended Response Actions

1. Investigate the initiating command and its source.
2. Analyze command-line arguments for malicious indicators.
3. Review system logs for follow-on process creation or network connections.
4. Examine for signs of credential exfiltration or browser data access.
5. Isolate affected systems if confirmed malicious.

---

## References

- [Microsoft: Lumma Stealer – Breaking down the delivery techniques and capabilities of a prolific infostealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK: T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1218 – Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [MITRE ATT&CK: T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-03 | Initial Detection | Created hunt query to detect suspicious RunMRU registry modifications linked to Lumma Stealer |
