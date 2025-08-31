# Detection of Suspicious AutoIt or .NET Executables from Temp

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AutoItDotNetDropper
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of suspicious AutoIt or .NET executables that are dropped by PowerShell scripts, typically into temporary or user application data directories. These executables often contain encrypted payloads, which are later executed or injected into other processes. Such activity is commonly associated with malware delivery, initial access, and post-exploitation techniques.

Detected behaviors include:

- Execution of `.exe` files from `Temp` or `AppData` directories
- Command lines referencing keywords such as `encrypted`, `shellcode`, or `DLLCALLADDRESS`
- Parent process is often PowerShell, indicating script-based delivery

These patterns are frequently observed in attacks involving commodity malware, loaders, and custom droppers.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution            | T1059.003   | —            | Command and Scripting Interpreter: AutoIt              |
| TA0011 - Command and Control  | T1071.001   | —            | Application Layer Protocol: Web Protocols              |

---

## Hunt Query Logic

This query identifies suspicious executable files that are likely dropped by PowerShell scripts and executed from temporary or user data directories. It focuses on command lines that reference encrypted payloads or shellcode, which are strong indicators of malicious activity.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/ProcessRollup2|ProcessCreation/
| (FileName = "*.exe")
| (FilePath = "*\\Temp\\*" OR FilePath = "*\\AppData\\*")
| (CommandLine = "*encrypted*" OR CommandLine = "*shellcode*" OR CommandLine = "*DLLCALLADDRESS*")
```

---

## Data Sources

| Log Provider | Event ID | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|--------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute files in Temp or AppData directories.
- **Required Artifacts:** Dropped executable files, PowerShell script logs, process creation events.

---

## Considerations

- Investigate the source PowerShell script and its contents.
- Analyze the dropped executable for obfuscation, packing, or encryption.
- Review network activity for potential C2 communications initiated by the dropped executable.
- Correlate with endpoint alerts for privilege escalation or lateral movement.

---

## False Positives

False positives may occur if:

- Legitimate software installers or updaters temporarily drop executables in Temp or AppData.
- Internal IT scripts automate software deployment using PowerShell and temporary files.
- Security tools or forensic utilities use similar techniques for legitimate purposes.

---

## Recommended Response Actions

1. Isolate the affected endpoint to prevent further execution.
2. Retrieve and analyze the dropped executable for malicious characteristics.
3. Review PowerShell logs and scripts for evidence of malicious activity.
4. Search for additional indicators of compromise (IOCs) across the environment.
5. Block or quarantine the identified files and associated scripts.

---

## References

- [MITRE ATT&CK: T1059.003 – AutoIt](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1071.001 – Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [Cascading Shadows: An Attack Chain Approach to Avoid Detection and Complicate Analysis](https://unit42.paloaltonetworks.com/phishing-campaign-with-complex-attack-chain/#new_tab)


---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-29 | Initial Detection | Created hunt query to detect suspicious AutoIt or .NET executables dropped by PowerShell    |
