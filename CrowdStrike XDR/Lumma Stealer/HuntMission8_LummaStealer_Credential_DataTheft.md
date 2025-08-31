# Detection of Credential and Sensitive Data Theft Activities

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-CredentialDataTheft
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt identifies potential credential and sensitive data theft activities associated with malware such as Lumma Stealer. The detection is based on anomalous access to specific file paths commonly associated with browser credentials, cryptocurrency wallets, remote access tools, and password managers. These behaviors are often part of credential harvesting and data exfiltration campaigns.

---

## ATT&CK Mapping

| Tactic                      | Technique | Subtechnique | Technique Name                         |
|----------------------------|-----------|--------------|----------------------------------------|
| TA0006 - Credential Access | T1555     | —            | Credentials from Password Stores       |
| TA0009 - Collection        | T1539     | —            | Steal Web Session Cookie               |
| TA0006 - Credential Access | T1552     | —            | Unsecured Credentials                  |
| TA0009 - Collection        | T1005     | —            | Data from Local System                 |

---

## Hunt Query Logic

This query looks for file and process activity accessing sensitive directories associated with:

- Browser-stored credentials (e.g., Chrome, Firefox)
- Password managers (e.g., KeePass)
- Remote desktop software (e.g., AnyDesk)
- Cryptocurrency wallets (e.g., MetaMask, Binance)

Legitimate browser processes are excluded to reduce noise.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/FileRead|ProcessRollup2/  
| in(field="TargetFilePath", values=["*\AppData\*\Google\Chrome\User Data\*", "*\AppData\*\Mozilla\Firefox\Profiles\*", "*\AppData\*\KeePass\*", "*\AppData\*\AnyDesk\*", "*\AppData\*\MetaMask\*", "*\AppData\*\Ethereum\*", "*\AppData\*\Binance\*"]) 
| NOT in(field="ImageFileName", values=["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"])  
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------------|---------------------|------------------------|
| Falcon       | FileRead, ProcessRollup2 | File, Process        | File Access, Process Creation |

---

## Execution Requirements

- **Required Permissions:** Read access to user application data directories.
- **Required Artifacts:** Access to browser data files, password manager files, and RDP-related configurations.

---

## Considerations

- Confirm if access to sensitive directories aligns with expected application behavior.
- Investigate the image/process responsible for the activity.
- Monitor for follow-up activity such as data staging or exfiltration attempts.

---

## False Positives

False positives may occur when:

- Legitimate utilities or scripts access application directories for backup or sync.
- Enterprise management tools conduct scans or gather telemetry.

---

## Recommended Response Actions

1. Validate the context of the accessing process.
2. Review file hashes and process lineage for indicators of compromise.
3. Inspect user activity and determine if access was expected or anomalous.
4. Check for subsequent outbound network connections or archive creation.
5. Consider containment if malicious intent is confirmed.

---

## References

- [MITRE ATT&CK: T1555 – Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [MITRE ATT&CK: T1539 – Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK: T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [Lumma Stealer – Tracking distribution channels](https://securelist.com/lumma-fake-captcha-attacks-analysis/116274/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-25 | Initial Detection | Created hunt query to detect credential and sensitive data theft activities  |
