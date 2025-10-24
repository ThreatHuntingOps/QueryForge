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

This query filters Windows registry `SetValue` events and flags modifications to `Run` or `RunOnce` keys. It then applies a regex match to detect value names that follow the Qilin asterisk pattern (`*` followed by exactly 6 alphanumeric characters). The query also enriches results by identifying whether the actor process is suspicious (i.e., not a known system process and not located in `C:\Windows\` or `C:\Program Files`).

Key points:
- Require registry event type = `SetValue` and key path contains `Run` or `RunOnce`
- Require value name to match regex: `^\*[A-Za-z0-9]{6}$`
- Flag suspicious actor process (non-system, non-Windows directory)

---

#### Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Qilin Ransomware - Safe Mode Registry Persistence with Asterisk Pattern
// MITRE: T1547.001, T1112
| #repo="base_sensor" event_platform="Win"

// Limit to registry set-value events
| #event_simpleName="RegistrySetValue"

// Initialize flags
| run_key_modification := 0
| qilin_asterisk_pattern := 0
| actor_in_windows_dir := 0
| actor_in_program_files := 0
| actor_is_system_proc := 0
| suspicious_actor := 0

// Phase 1: Registry modification in Run / RunOnce keys
| (
    #event_simpleName="RegistrySetValue" and
    (RegistryKeyPath=/CurrentVersion\\Run/i or RegistryKeyPath=/CurrentVersion\\RunOnce/i)
  ) | run_key_modification := 1

// Phase 2: Asterisk-prefixed 6-character value name pattern (e.g., "*ABC123")
| (
    #event_simpleName="RegistrySetValue" and
    RegistryValueName=/^\*[A-Za-z0-9]{6}$/i
  ) | qilin_asterisk_pattern := 1

// Phase 3: Actor process location checks and system-process exclude list
| (
    ImageFilePath=/c:\\\\windows\\\\/i
  ) | actor_in_windows_dir := 1

| (
    ImageFilePath=/c:\\\\program files/i
  ) | actor_in_program_files := 1

| (
    ImageFileName=/\\b(explorer\\.exe|winlogon\\.exe|userinit\\.exe|services\\.exe|reg\\.exe|regedit\\.exe)$/i
  ) | actor_is_system_proc := 1

// suspicious_actor: actor path exists AND not in Windows/Program Files AND not a known system proc
| ImageFilePath!="" and actor_in_windows_dir=0 and actor_in_program_files=0 and actor_is_system_proc=0 | suspicious_actor := 1

// Correlation: Run key modification + asterisk-prefixed value name
| run_key_modification=1 and qilin_asterisk_pattern=1

// Enrichment / classification
| detection_category := "Registry Persistence Detected"
| qilin_asterisk_pattern=1 | detection_category := "Asterisk-Prefixed Registry Persistence (High Suspicion)"
| qilin_asterisk_pattern=1 and suspicious_actor=1 | detection_category := "Qilin Ransomware Persistence (Confirmed)"

// Risk scoring (numeric)
| risk_score := 85
| qilin_asterisk_pattern=1                                     | risk_score := 95
| qilin_asterisk_pattern=1 and suspicious_actor=1             | risk_score := 100

// Human-friendly safe_mode indicator (string)
| safe_mode_enabled := "No"
| qilin_asterisk_pattern=1 | safe_mode_enabled := "Yes (asterisk prefix)"

// Output
| select([
    aid,
    ComputerName,
    _time,
    RegistryKeyPath,
    RegistryValueName,
    RegistryValueType,
    RegistryValueData,
    ImageFilePath,
    ImageFileName,
    UserName,
    run_key_modification,
    qilin_asterisk_pattern,
    suspicious_actor,
    detection_category,
    risk_score,
    safe_mode_enabled,
    #event_simpleName
  ])
| sort([risk_score, _time], order=desc)
```

---

#### Data Sources

| Provider                 | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component         |
|-------------------------|-----------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon      | Windows Registry                                          |  Registry          |Registry Modification     |


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
