# Safe Mode Registry Persistence with Asterisk Pattern

#### Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** Critical

#### Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Qilin-Asterisk-Registry-Persistence
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low

---

#### Hunt Analytics

This hunt detects Qilin ransomware's unique registry persistence mechanism: the creation of a Run key value with a name matching the pattern `*<6_random_characters>` (e.g., `*Ab3Xk9`). The asterisk prefix is a sophisticated evasion technique that allows the binary to execute in Windows Safe Mode, bypassing many security tools and recovery attempts.

This is one of the highest-fidelity Qilin indicators, with virtually zero false positives in normal environments. The detection focuses on registry `SetValue` events in `CurrentVersion\Run` or `CurrentVersion\RunOnce` keys where the value name matches the Qilin asterisk pattern. Additional confidence is gained when the registry modification is made by a non-system process from a suspicious location.

Detected behaviors include:

- Registry modifications to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` or `RunOnce`
- Value names matching the regex `^\*[A-Za-z0-9]{6}$`
- Registry changes made by non-system processes (e.g., not explorer.exe, services.exe, etc.)

---

#### ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence         | T1547.001   | -            | Boot or Logon Autostart Execution: Registry Run Keys |
| TA0005 - Defense Evasion     | T1112       | -            | Modify Registry                               |

---

#### Hunt Query Logic

This XQL query filters Windows registry `SetValue` events and flags modifications to `Run` or `RunOnce` keys. It then applies a regex match to detect value names that follow the Qilin asterisk pattern (`*` followed by exactly 6 alphanumeric characters). The query also enriches results by identifying whether the actor process is suspicious (i.e., not a known system process and not located in `C:\Windows\` or `C:\Program Files`).

Key points:
- Require registry event type = `SetValue` and key path contains `Run` or `RunOnce`
- Require value name to match regex: `^\*[A-Za-z0-9]{6}$`
- Flag suspicious actor process (non-system, non-Windows directory)

---

#### Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR / XSIAM

```xql
// Qilin Ransomware - Safe Mode Registry Persistence with Asterisk Pattern
// MITRE: T1547.001 (Run Keys), T1112 (Modify Registry)
// OS: Windows

config case_sensitive = false
| dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter event_type = REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE

// Phase 1: Detect registry modification in Run / RunOnce keys
| alter run_key_modification = if(
  action_registry_key_name != null and
  (action_registry_key_name contains "CurrentVersion\\Run" or action_registry_key_name contains "CurrentVersion\RunOnce"),
  true, false
)

// Phase 2: Detect asterisk-prefixed 6-character value name pattern (Qilin signature)
| alter qilin_asterisk_pattern = if(
  action_registry_value_name != null and action_registry_value_name ~= "^\\*[A-Za-z0-9]{6}$",
  true, false
)

// Phase 3: Detect non-system process making modification
| alter actor_in_windows_dir = if(actor_process_image_path != null and actor_process_image_path contains "c:\windows\", true, false)
| alter actor_in_program_files = if(actor_process_image_path != null and actor_process_image_path contains "c:\program files", true, false)
| alter actor_is_system_proc = if(
  actor_process_image_name != null and
  (actor_process_image_name contains "explorer.exe" or
   actor_process_image_name contains "winlogon.exe" or
   actor_process_image_name contains "userinit.exe" or
   actor_process_image_name contains "services.exe" or
   actor_process_image_name contains "reg.exe" or
   actor_process_image_name contains "regedit.exe"),
  true, false
)
| alter suspicious_actor = if(
  actor_process_image_path != null and
  (actor_in_windows_dir = false and actor_in_program_files = false and actor_is_system_proc = false),
  true, false
)

// Correlation
| filter run_key_modification = true and qilin_asterisk_pattern = true

// Enrichment
| alter detection_category = "Registry Persistence Detected"
| alter detection_category = if(qilin_asterisk_pattern = true, "Asterisk-Prefixed Registry Persistence (High Suspicion)", detection_category)
| alter detection_category = if(qilin_asterisk_pattern = true and suspicious_actor = true, "Qilin Ransomware Persistence (Confirmed)", detection_category)

| alter risk_score = 85
| alter risk_score = if(qilin_asterisk_pattern = true, 95, risk_score)
| alter risk_score = if(qilin_asterisk_pattern = true and suspicious_actor = true, 100, risk_score)

| alter safe_mode_enabled = if(qilin_asterisk_pattern = true, "Yes (asterisk prefix)", "No")

// Output
| fields
  agent_hostname,
  _time,
  action_registry_key_name,
  action_registry_value_name,
  action_registry_value_type,
  action_registry_data,
  actor_process_image_path,
  actor_effective_username,
  run_key_modification,
  qilin_asterisk_pattern,
  suspicious_actor,
  detection_category,
  risk_score,
  safe_mode_enabled
| sort desc risk_score, desc _time
```

---

#### Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Windows Registry    | Registry Modification  |

---

#### Execution Requirements

- **Required Permissions:** Collection of registry `SetValue` events with full key path, value name, and actor process information.
- **Required Artifacts:** Registry modification logs, actor process image path, and effective username.

---

#### Considerations

- This is a highly specific indicator of Qilin ransomware and is unlikely to be used by other malware families.
- The asterisk prefix enables execution in Safe Mode, which is a strong evasion technique. This should be treated as a confirmed persistence mechanism.
- Correlate with other Qilin indicators (VSS deletion, event log clearing, password-protected execution) to confirm compromise.

---

#### False Positives

False positives are extremely unlikely due to the highly specific regex pattern and the Safe Mode execution technique. No legitimate software is known to use this pattern.

---

#### Recommended Response Actions

1. Immediately isolate the affected host and preserve registry hives for forensic analysis.
2. Query for related activity from the same host or user (e.g., file encryption, ransom note creation, lateral movement).
3. Collect memory and process artifacts for forensic analysis.
4. Block or quarantine the binary associated with the registry modification.
5. Notify incident response and follow organizational ransomware playbooks for containment, eradication, and recovery.
6. Review registry backups or system restore points to remove the malicious entry if needed.

---

#### References

- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)

---

#### Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-23 | Initial Detection | Created hunt query to detect Qilin's asterisk-prefixed registry persistence for Safe Mode execution |
