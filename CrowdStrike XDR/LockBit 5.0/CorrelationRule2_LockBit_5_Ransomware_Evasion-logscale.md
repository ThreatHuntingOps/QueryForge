# Ransomware Execution with Advanced Evasion Techniques

## Severity or Impact of the Detected Behavior
- **Risk Score:** 96 (Encryption detected with process injection and evasion indicators)
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-Ransomware-Evasion-Techniques
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low (requires encryption + multiple advanced phases)
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Analytics
This correlation rule detects LockBit 5.0 ransomware execution when paired with advanced evasion and injection techniques, ensuring high-confidence alerts.

Detected behaviors include:
- Encryption Activity: File writes, renames, or creation of ransom notes (`ReadMeForDecrypt.txt`, `decrypt.txt`).
- Process Injection: Memory manipulation functions such as `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, or `NtMapViewOfSection`.
- Anti-analysis & ETW evasion: Calls to methods like `EtwEventWrite`, `IsDebuggerPresent`, and suspicious Base64 command-line arguments.
- Reconnaissance: System and environment discovery commands (`whoami`, `hostname`, `systeminfo`, `net view`, `tasklist`, `locale`).

Correlation requires encryption + at least two other phases (injection, evasion, reconnaissance), minimizing false positives and surfacing critical attack chains.

---

## ATT&CK Mapping

| Tactic           | Technique | Subtechnique | Technique Name                                    |
|------------------|----------:|-------------:|---------------------------------------------------|
| Impact           | T1486     | -            | Data Encrypted for Impact                         |
| Defense Evasion  | T1055     | -            | Process Injection                                 |
| Defense Evasion  | T1027     | -            | Obfuscated/Encrypted Files or Information         |
| Defense Evasion  | T1562     | .006         | Impair Defenses: Disable Windows Event Logging    |

---

## Query Logic
This analytic detects ransomware encryption paired with advanced evasion phases.
- Mandatory encryption indicators must be present.
- Requires two other phases among process injection, evasion, or reconnaissance.

This ensures the rule only triggers on multi-faceted ransomware activity rather than benign or isolated behaviors.

---

## Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Ransomware Execution with Advanced Evasion Techniques
// Phases: Encryption activity + at least two of: Injection, Evasion, Recon

| #repo="base_sensor" event_platform="Win"

// Limit to relevant event families (process + file ops)
| (
    #event_simpleName="ProcessRollup2" or
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="FileRename" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten"
  )

// Initialize phase flags
| encryption_activity := 0
| injection_activity := 0
| evasion_activity := 0
| recon_activity := 0

// Phase 1: File Encryption Activity
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="FileRename") and
    (FileName=/\\.([A-Za-z0-9]{16})$/ or TargetFileName=/\\.([A-Za-z0-9]{16})$/)
  ) | encryption_activity := 1

| (
    #event_simpleName="NewFileWritten" and
    (FileName=/(ReadMeForDecrypt|decrypt|ransom).*\\.txt/i or TargetFileName=/(ReadMeForDecrypt|decrypt|ransom).*\\.txt/i)
  ) | encryption_activity := 1

// Phase 2: Process Injection Indicators
| (
    #event_simpleName="ProcessRollup2" and
    (CommandLine=/VirtualAllocEx/i or
     CommandLine=/WriteProcessMemory/i or
     CommandLine=/CreateRemoteThread/i or
     CommandLine=/QueueUserAPC/i or
     CommandLine=/NtMapViewOfSection/i)
  ) | injection_activity := 1

// Phase 3: Anti-Analysis and ETW Evasion
| (
    #event_simpleName="ProcessRollup2" and
    (CommandLine=/EtwEventWrite/i or
     CommandLine=/IsDebuggerPresent/i or
     CommandLine=/CheckRemoteDebuggerPresent/i or
     CommandLine=/[A-Za-z0-9+\\/]{30,}={0,2}/)
  ) | evasion_activity := 1

// Phase 4: System Reconnaissance
| (
    #event_simpleName="ProcessRollup2" and
    (CommandLine=/\\bwhoami\\b/i or
     CommandLine=/\\bhostname\\b/i or
     CommandLine=/\\bsysteminfo\\b/i or
     CommandLine=/\\bnet\\s+view\\b/i or
     CommandLine=/\\btasklist\\b/i or
     CommandLine=/\\blocale\\b/i)
  ) | recon_activity := 1

// Build a numeric sum for correlation without bare expressions
| phase_sum := 0
| injection_activity=1 | phase_sum := phase_sum + 1
| evasion_activity=1   | phase_sum := phase_sum + 1
| recon_activity=1     | phase_sum := phase_sum + 1

// Correlation: require encryption + at least 2 other phases
| encryption_activity=1
| phase_sum>=2

// Classification (stepwise, guarded updates)
| detection_category := "Ransomware Execution Detected"
| ((injection_activity=1 and evasion_activity=1) or (injection_activity=1 and recon_activity=1) or (evasion_activity=1 and recon_activity=1)) | detection_category := "Medium-Impact Ransomware Attack"
| (injection_activity=1 and evasion_activity=1 and recon_activity=1) | detection_category := "High-Impact Ransomware Attack"

| severity := "HIGH"
| mitre_techniques := "T1486,T1055,T1562.001,T1059,T1082"

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
    encryption_activity,
    injection_activity,
    evasion_activity,
    recon_activity,
    phase_sum,
    detection_category,
    severity,
    mitre_techniques,
    #event_simpleName
])
| sort([@timestamp], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon) | ATT&CK Data Source | Data Component                 |
|--------------------|--------------------------|--------------------|--------------------------------|
| CrowdStrike Falcon | base_sensor              | File               | File Write / File Creation     |
| CrowdStrike Falcon | base_sensor              | Process            | Process Creation               |
| CrowdStrike Falcon | base_sensor              | Registry           | Registry Modification          |

---

## Execution Requirements
- Required Permissions: Elevated privileges often required for injection and evasion.
- Required Artifacts: File and process telemetry with command line arguments.

---

## Considerations
- LockBit 5.0 leverages multi-phase techniques combining injection, evasion, and reconnaissance with encryption.
- Detection prioritizes advanced correlations, avoiding trivial triggers from single activity phases.
- Tune ransom-note patterns for environment-specific variants if observed.

---

## False Positives
- Rare. Edge cases include legitimate admin scripts running reconnaissance (whoami, systeminfo). Correlation with encryption drastically reduces benign matches.

Mitigations:
- Correlate with change windows/tickets
- Maintain allowlists for sanctioned scripts/tools

---

## Recommended Response Actions
1. Isolate impacted systems immediately.
2. Terminate malicious processes exhibiting injection or ETW evasion.
3. Search for ransom notes and encrypted files across file systems.
4. Investigate reconnaissance attempts for lateral movement preparation.
5. Escalate to incident response teams for containment and remediation.

---

## References
- [MITRE ATT&CK T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1027 – Obfuscated/Encrypted Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK T1562.006 – Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/006/)

---

## Version History

| Version | Date       | Impact                                | Notes                                     |
|---------|------------|---------------------------------------|-------------------------------------------|
| 1.0     | 2025-10-06 | Initial Release of Evasion Techniques | Added injection + evasion + recon phases. |
