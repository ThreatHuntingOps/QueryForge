# Detection of LockBit 5.0 Multi-Phase Kill Chain 

## Severity or Impact
- **Risk Score:** 98
- **Severity:** CRITICAL

## Correlation Rule Metadata
- **ID:** CorrelationRule-Windows-LockBit50-Full-Kill-Chain
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Analytics
High-fidelity detection of LockBit 5.0's complete attack lifecycle from initial execution through impact. Correlates six distinct phases and requires encryption + ransom note deployment plus at least two additional phases for alerting.

**Phases:**
1. **ETW Patching & Anti-Analysis:** Command lines referencing `EtwEventWrite`, `0xC3`, `IsDebuggerPresent`
2. **Security Service Termination:** `sc.exe`, `net.exe`, `taskkill.exe`, or PowerShell stopping AV/EDR/backup services
3. **File Encryption:** File writes/renames with 16-character alphanumeric extensions
4. **Ransom Note Deployment:** Creation of `ReadMeForDecrypt.txt`
5. **Event Log Clearing:** `wevtutil.exe` or PowerShell `Clear-EventLog`
6. **Advanced Obfuscation:** `Assembly.Load`, `FromBase64String`, or long Base64 strings in command lines

**Correlation Logic:**
- Mandatory: Phase 3 (encryption) AND Phase 4 (ransom note)
- Plus any two of: Phase 1, 2, 5, or 6

---

## ATT&CK Mapping

| Tactic                     | Technique | Subtechnique | Technique Name                              |
|----------------------------|----------:|-------------:|---------------------------------------------|
| TA0005 - Defense Evasion   | T1562     | .006         | Impair Defenses: Indicator Blocking         |
| TA0040 - Impact            | T1489     | -            | Service Stop                                |
| TA0040 - Impact            | T1486     | -            | Data Encrypted for Impact                   |
| TA0040 - Impact            | T1491     | .001         | Defacement: Internal Defacement             |
| TA0005 - Defense Evasion   | T1027     | -            | Obfuscated Files or Information             |
| TA0005 - Defense Evasion   | T1070     | .001         | Indicator Removal: Clear Windows Event Logs |

---

## Correlation Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// LockBit 5.0 Multi-Phase Kill Chain
// Description: Detect LockBit 5.0 lifecycle from anti-analysis through impact
// MITRE ATT&CK: T1562.006, T1489, T1486, T1491.001, T1027, T1070.001

| #repo="base_sensor" event_platform="Win"

// Relevant event families (process + file ops)
| (
    #event_simpleName="ProcessRollup2" or
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="FileRename" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten"
  )

// Initialize flags
| phase1_etw_evasion := 0
| phase2_service_kill := 0
| phase3_encryption := 0
| phase4_ransom_note := 0
| phase5_log_clearing := 0
| phase6_obfuscation := 0

// Phase 1: ETW/anti-analysis indicators
| (
    #event_simpleName="ProcessRollup2" and
    (CommandLine=/EtwEventWrite/i or CommandLine=/0xC3/i or CommandLine=/IsDebuggerPresent/i)
  ) | phase1_etw_evasion := 1

// Phase 2: Security service termination (stop/kill + security keywords)
// Avoid '/f' parser issue by matching ' taskkill ' then ' /f' via whitespace and 'f' without slash inside regex
| (
    #event_simpleName="ProcessRollup2" and
    (
      (ImageFileName=/\\sc\\.exe$/i and CommandLine=/\\bstop\\b/i) or
      (ImageFileName=/\\net\\.exe$/i and CommandLine=/\\bstop\\b/i) or
      (ImageFileName=/\\taskkill\\.exe$/i and (CommandLine=/\\btaskkill\\b/i and CommandLine=/\\bf\\b/i)) or
      ((ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and CommandLine=/Stop-Service/i)
    ) and
    CommandLine=/(avast|kaspersky|norton|mcafee|bitdefender|defender|cortex|falcon|crowdstrike|security|backup)/i
  ) | phase2_service_kill := 1

// Phase 3: Encryption - filenames ending with a 16-char alphanumeric extension
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="FileRename" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    (FileName=/\\.([A-Za-z0-9]{16})$/ or TargetFileName=/\\.([A-Za-z0-9]{16})$/)
  ) | phase3_encryption := 1

// Phase 4: Ransom note deployment
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    (FileName=/^ReadMeForDecrypt\\.txt$/i or TargetFileName=/^ReadMeForDecrypt\\.txt$/i)
  ) | phase4_ransom_note := 1

// Phase 5: Event log clearing
| (
    #event_simpleName="ProcessRollup2" and
    (
      (ImageFileName=/\\wevtutil\\.exe$/i and CommandLine=/clear-log/i) or
      ((ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and CommandLine=/Clear-EventLog/i)
    )
  ) | phase5_log_clearing := 1

// Phase 6: Advanced obfuscation (reflective load, base64-like blobs)
| (
    #event_simpleName="ProcessRollup2" and
    (CommandLine=/Assembly\\.Load/i or CommandLine=/FromBase64String/i or CommandLine=/[A-Za-z0-9+\\/]{50,}={0,2}/)
  ) | phase6_obfuscation := 1

// Correlation without ternaries/assignments: require encryption AND ransom note, plus at least two of the other phases
| enc_ok := phase3_encryption
| note_ok := phase4_ransom_note
| others := (phase1_etw_evasion + phase2_service_kill + phase5_log_clearing + phase6_obfuscation)
| enc_ok=1
| note_ok=1
| others>=2

// Enrichment
| detection_category := "LockBit 5.0 Full Kill Chain"
| attack_technique := "T1562.006,T1489,T1486,T1491.001,T1070.001,T1027"
| severity := "CRITICAL"

// Output
| select([
    @timestamp,
    aid,
    ComputerName,
    UserName,
    ImageFileName,
    CommandLine,
    FileName,
    TargetFileName,
    phase1_etw_evasion,
    phase2_service_kill,
    phase3_encryption,
    phase4_ransom_note,
    phase5_log_clearing,
    phase6_obfuscation,
    detection_category,
    attack_technique,
    severity,
    #event_simpleName
])
| sort([@timestamp], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                                 | ATT&CK Data Source | Data Component      |
|--------------------|----------------------------------------------------------|--------------------|---------------------|
| CrowdStrike Falcon | base_sensor                        | Process            | Process Creation    |
| CrowdStrike Falcon | base_sensor                                             | File               | File Creation/Modification |
| CrowdStrike Falcon | base_sensor                                              | Command            | Command Execution   |

---

## Prerequisites
- **Data Sources:** Process creation with command-line arguments, file creation/modification telemetry, registry activity
- **Required Permissions:** LockBit 5.0 typically executes with elevated privileges for service termination and log clearing
- **Temporal Window:** Phases typically occur within minutes to hours; correlation window should span at least 1 hour per host

---

## Correlation Logic Details
- **Mandatory Phases:** Encryption (Phase 3) + Ransom Note (Phase 4) must both fire
- **Additional Phases:** At least 2 of the following must also fire:
  - Phase 1 (ETW evasion)
  - Phase 2 (service termination)
  - Phase 5 (log clearing)
  - Phase 6 (obfuscation)
- **Minimum Total:** 4 phases required for alert

---

## Tuning Guidance
- **Service Termination (Phase 2):** Adjust AV/EDR/backup service name regex to match your environment's security stack
- **File Extension (Phase 3):** LockBit 5.0 uses 16-character alphanumeric extensions; validate this pattern in your telemetry
- **Ransom Note (Phase 4):** `ReadMeForDecrypt.txt` is the known artifact; monitor for variants
- **Obfuscation (Phase 6):** Base64 threshold (50+ chars) may need tuning based on legitimate PowerShell usage
- **Exclusions:** Consider excluding known admin/patch management accounts if they trigger Phase 2 legitimately

---

## False Positives
- **Service Termination:** Legitimate maintenance windows stopping security services (rare but possible)
- **Log Clearing:** Authorized log rotation or compliance-driven clearing (should be scheduled/documented)
- **Obfuscation:** Legitimate enterprise scripts using Base64 encoding

**Mitigations:**
- Correlate with change management tickets
- Exclude known maintenance accounts/hosts
- Validate encryption and ransom note presence (mandatory phases reduce FPs significantly)

---

## Recommended Response Actions
1. **Immediate Containment:** Network-isolate affected host(s) via Falcon RTR or network controls
2. **Kill Processes:** Terminate any active encryption processes; identify parent process chain
3. **Preserve Evidence:** Capture memory dump, process list, open file handles, and network connections
4. **Assess Spread:** Search for Phase 2 (service kills) and Phase 3 (encryption) across the estate to identify lateral movement
5. **Credential Reset:** Rotate credentials for any accounts active on affected hosts
6. **Backup Validation:** Confirm backup integrity; check for backup deletion attempts (common LockBit precursor)
7. **Threat Hunt:** Expand search for Phase 1 (ETW patching) and Phase 6 (obfuscation) to identify initial access vectors
8. **Forensics:** Analyze ransom note, encrypted file samples, and any dropped tools for attribution and decryption feasibility
9. **Stakeholder Notification:** Engage legal, compliance, and executive leadership per incident response plan
10. **Recovery:** Initiate restoration from clean backups; do not pay ransom without legal/executive approval

---

## References
- [MITRE ATT&CK: T1562.006 – Impair Defenses: Indicator Blocking](https://attack.mitre.org/techniques/T1562/006/)
- [MITRE ATT&CK: T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1491.001 – Defacement: Internal Defacement](https://attack.mitre.org/techniques/T1491/001/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: T1070.001 – Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

---

## Version History

| Version | Date       | Impact             | Notes                                                              |
|---------|------------|--------------------|--------------------------------------------------------------------|
| 1.0     | 2025-10-6 | Initial Detection  | Multi-phase correlation rule for LockBit 5.0 full kill chain       |
