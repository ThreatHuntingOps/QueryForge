# Advanced Persistence with High-Impact File Encryption 

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97 (Persistence combined with mass encryption and evasion)
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-Advanced-Persistence-Encryption
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Extremely Low (requires persistence + encryption + evasion)
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Analytics
Detects LockBit 5.0 leveraging persistence and high-impact file encryption consistent with enterprise-wide ransomware operations.

Detected behaviors include:
- Persistence: Registry Run/RunOnce keys or scheduled task creation via schtasks.exe
- Mass File Encryption: Files renamed/written with unique 16-character extensions
- Service Disruption: Killing/stopping AV/backup/security services
- Anti-forensics: Clearing event logs via wevtutil or PowerShell cmdlets
- Network Spread Indicators: psexec, wmic, net use/share, or UNC file copies

High-fidelity correlation requires mass encryption + persistence evidence along with at least one evasion technique (service disruption, anti-forensics, or network spread).

---

## ATT&CK Mapping

| Tactic           | Technique | Subtechnique | Technique Name                                    |
|------------------|----------:|-------------:|---------------------------------------------------|
| Persistence      | T1547     | .001         | Boot or Logon Autostart: Registry Run Keys        |
| Persistence      | T1053     | .005         | Scheduled Task/Job: Scheduled Task                |
| Impact           | T1486     | -            | Data Encrypted for Impact                         |
| Impact           | T1489     | -            | Service Stop                                      |
| Defense Evasion  | T1070     | .001         | Indicator Removal: Clear Windows Event Logs       |

---

## Query Logic
This analytic requires persistence -> encryption -> evasion to trigger:
1. Persistence -> Reg Run keys or scheduled tasks
2. Encryption -> mass file encryption with 16-char extensions
3. At least one evasion technique -> service disruption, log clearing, or lateral spread indicators

Together, these phases signal a large-scale, enterprise ransomware attack in progress.

---

## Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Advanced Persistence with High-Impact File Encryption
// MITRE ATT&CK: T1547.001,T1053.005,T1486,T1489,T1070.001

| #repo="base_sensor" event_platform="Win"

// Limit to relevant event families
| (
    #event_simpleName="ProcessRollup2" or          // process creations
    #event_simpleName="NewFileWritten" or          // file writes/creates
    #event_simpleName="FileWritten" or
    #event_simpleName="FileRename" or              // file renames (extension changes)
    #event_simpleName="RegistrySetValue"           // registry set value
  )

// Initialize phase flags
| persistence_mechanism := 0
| mass_encryption := 0
| service_disruption := 0
| anti_forensics := 0
| network_spread := 0

// Persistence: Registry Run keys (Run/RunOnce) or scheduled task creation via schtasks.exe
| (
    #event_simpleName="RegistrySetValue" and
    (RegistryKeyPath=/\\(run|runonce)\\?/i or RegistryKeyPath=/\\(run|runonce)$/i or RegistryKeyPath=/\\(run|runonce)\\[^\\]+/i)
  ) | persistence_mechanism := 1

| (
    #event_simpleName="ProcessRollup2" and
    ImageFileName=/\\schtasks\\.exe$/i and
    CommandLine=/\\bcreate\\b/i
  ) | persistence_mechanism := 1

// Impact: Mass file encryption (filenames ending with a 16-char alphanumeric extension)
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="FileRename") and
    (FileName=/\\.([A-Za-z0-9]{16})$/ or TargetFileName=/\\.([A-Za-z0-9]{16})$/)
  ) | mass_encryption := 1

// Defense evasion: Service disruption (stop/kill + security-related)
| (
    #event_simpleName="ProcessRollup2" and
    (
      ((ImageFileName=/\\sc\\.exe$/i or ImageFileName=/\\net\\.exe$/i) and CommandLine=/\\bstop\\b/i) or
      (ImageFileName=/\\taskkill\\.exe$/i and CommandLine=/(security|backup|antivirus)/i)
    )
  ) | service_disruption := 1

// Anti-forensics: Log clearing
| (
    #event_simpleName="ProcessRollup2" and
    (
      (ImageFileName=/\\wevtutil\\.exe$/i and CommandLine=/clear-log/i) or
      ((ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and CommandLine=/Clear-EventLog/i)
    )
  ) | anti_forensics := 1

// Network spread indicators (PsExec/WMI/net use/share/copy to UNC)
| (
    #event_simpleName="ProcessRollup2" and
    (
      CommandLine=/\\bpsexec\\b/i or
      CommandLine=/\\bwmic\\b/i or
      CommandLine=/\\bnet\\s+use\\b/i or
      CommandLine=/\\bnet\\s+share\\b/i or
      (CommandLine=/\\bcopy\\b/i and CommandLine=/^\\\\\\\\[^\\]+\\/i)   // copy to UNC path
    )
  ) | network_spread := 1

// High-fidelity: require mass encryption + persistence + at least one evasion technique
| mass_encryption=1
| persistence_mechanism=1
| (service_disruption=1 or anti_forensics=1 or network_spread=1)

// Indicators for impact assessment
| has_encryption_and_persistence := 0
| (mass_encryption=1 and persistence_mechanism=1) | has_encryption_and_persistence := 1

| has_multi_directory_indicators := 0
| TargetFileName=/\\(Documents|Desktop|Pictures|Videos)\\?/i or TargetFilePath=/\\(Documents|Desktop|Pictures|Videos)\\?/i | has_multi_directory_indicators := 1

// Category assignment (stepwise)
| detection_category := "Persistent Ransomware Attack"
| has_multi_directory_indicators=1 | detection_category := "Large-Scale Ransomware Attack"
| network_spread=1 | detection_category := "LockBit Enterprise Network Attack"

| attack_technique := "T1547.001,T1053.005,T1486,T1489,T1070.001"
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
    RegistryKeyPath,
    has_encryption_and_persistence,
    has_multi_directory_indicators,
    persistence_mechanism,
    mass_encryption,
    service_disruption,
    anti_forensics,
    network_spread,
    detection_category,
    attack_technique,
    severity,
    #event_simpleName
])
| sort([@timestamp], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon) | ATT&CK Data Source | Data Component                 |
|--------------------|--------------------------|--------------------|--------------------------------|
| CrowdStrike Falcon | base_sensor              | File               | File Write / File Rename       |
| CrowdStrike Falcon | base_sensor              | Process            | Process Creation               |
| CrowdStrike Falcon | base_sensor              | Registry           | Registry Modification          |

---

## Execution Requirements
- Required Permissions: Elevated privileges to write registry and schedule tasks.
- Required Artifacts: Registry, process, and file telemetry.

---

## Considerations
- Persistence artifacts ensure re-execution after reboot/login.
- Coupling persistence with network spread is strong evidence of enterprise compromise.
- Widespread encryption across user directories (Documents, Desktop, Pictures) confirms high impact.

---

## False Positives
- Possible admin usage of schtasks.exe or service control tools, but the combination with mass encryption and 16-character extensions makes benign triggers unlikely.

Mitigations:
- Validate against change windows / maintenance activities
- Maintain allowlists for sanctioned admin tools

---

## Recommended Response Actions
1. Quarantine affected endpoints exhibiting persistence + encryption.
2. Inspect scheduled tasks and registry run keys for persistence artifacts.
3. Review disabled/killed services and restore security coverage.
4. Identify network spread attempts (psexec, wmic) across the environment.
5. Correlate directory impact (Documents, Desktop, Pictures) to scope data loss.
6. Initiate enterprise ransomware response playbooks.

---

## References
- [MITRE ATT&CK T1547.001 – Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK T1053.005 – Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK T1070.001 – Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

---

## Version History

| Version | Date       | Impact                                   | Notes                                       |
|---------|------------|------------------------------------------|---------------------------------------------|
| 1.0     | 2025-10-01 | Initial Release                          | Persistence + encryption + evasion combined |
