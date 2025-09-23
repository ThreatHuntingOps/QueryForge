# Detection of User Account Hidden from Logon Screen

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Reg-HideUserAccount
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a specific registry modification used to hide a user account from the Windows Welcome and logon screens. Threat actors, including the Chaos ransomware group, use this technique to create a stealthy user account for persistence. The hidden account remains active and accessible via RDP or other remote access methods but is not visible to a user logging in locally. This is a high-fidelity indicator of an attempt to create a hidden backdoor account.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0003 - Persistence          | T1098       | —            | Account Manipulation                           |
| TA0005 - Defense Evasion      | T1112       | —            | Modify Registry                                |

---

## Hunt Query Logic

This query identifies this persistence technique by monitoring for any creation or modification events within the following registry path:
`\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist`

Any new entry under this key corresponds to a user account that will be hidden from the UI.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: User Account Hidden via SpecialAccounts Registry Modification
// Description: Detects the creation or modification of a registry key under Winlogon\SpecialAccounts\Userlist, a technique used to hide a user account from the logon screen for stealthy persistence.
// MITRE ATT&CK TTP ID: T1098

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.REGISTRY 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_registry_key_name contains "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist" 
| fields _time, agent_hostname, actor_effective_username, action_registry_key_name, action_registry_value_name, action_registry_data, actor_process_image_name, actor_process_image_path, actor_process_command_line, event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Registry            | Registry Key Modification |

---

## Execution Requirements

- **Required Permissions:** The attacker must have administrative privileges to modify the HKEY_LOCAL_MACHINE (HKLM) portion of the registry.
- **Required Artifacts:** Registry modification event logs.

---

## Considerations

- **High Fidelity:** This is a very specific technique with almost no legitimate use cases in a standard enterprise environment. Alerts should be treated as high priority.
- **Username in Key:** The username of the account being hidden is typically the registry value name (`action_registry_value_name`) created under the `UserList` key.
- **Investigate Actor Process:** The process that made the registry change (`actor_process_image_name`) is the immediate culprit and should be investigated thoroughly.

---

## False Positives

- False positives are extremely rare. Some obscure system customization tools might use this functionality, but it is not standard behavior for any common software. Any alert should be considered a likely true positive until proven otherwise.

---

## Recommended Response Actions

1.  **Investigate Account:** Immediately investigate the user account that was hidden. Check its group memberships (e.g., Administrators), recent logon activity, and other associated actions.
2.  **Isolate Host:** Isolate the affected endpoint from the network to prevent any remote access via the hidden account.
3.  **Disable Account:** Disable the hidden user account.
4.  **Analyze Actor:** Investigate the process that performed the registry modification to understand the initial vector and scope of the compromise.
5.  **Remediate:** Remove the malicious registry entry and remediate the host based on the findings of the investigation.

---

## References

- [MITRE ATT&CK: T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK: T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created hunt query to detect the hiding of user accounts via the registry. |
