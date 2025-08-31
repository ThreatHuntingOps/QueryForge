# Detection of Process Injection into RegSvcs.exe

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RegSvcsInjection
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium

---

## Hunt Analytics

This hunt detects process injection into the legitimate Microsoft process `RegSvcs.exe` by a parent process of either `AutoIt.exe` or `dotnet.exe`. Attackers often leverage process injection into trusted system binaries like RegSvcs.exe to evade security controls and maintain persistence. The query focuses on suspicious parent-child relationships, execution from user-writable directories, and command lines indicating injection or association with `RegAsm.exe`.

Detected behaviors include:

- Execution of `RegSvcs.exe` from `AppData` or `Temp` directories
- Parent process is `AutoIt.exe` or `dotnet.exe`
- Command line contains keywords such as `injected` or references to `RegAsm.exe`

Such activity is strongly associated with malware delivery, privilege escalation, and defense evasion.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0005 - Defense Evasion      | T1055.003   | —            | Process Injection (via RegSvcs.exe)                    |
| TA0011 - Command and Control  | T1071.001   | —            | Application Layer Protocol: Web Protocols              |

---

## Hunt Query Logic

This query identifies suspicious executions of `RegSvcs.exe` where the parent process is either `AutoIt.exe` or `dotnet.exe`, the process is running from a user-writable directory, and the command line contains indicators of injection or references to `RegAsm.exe`.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/ProcessRollup2|ProcessCreation/
| (FileName = "RegSvcs.exe")
| (ParentBaseFileName = "AutoIt.exe" OR ParentBaseFileName = "dotnet.exe")
| (FilePath = "*\\AppData\\*" OR FilePath = "*\\Temp\\*")
| (CommandLine = "*injected*" OR CommandLine = "*RegAsm.exe*")
```

---

## Data Sources

| Log Provider | Event ID | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|--------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute and inject into RegSvcs.exe.
- **Required Artifacts:** Process creation logs, parent-child process relationships, command-line arguments.

---

## Considerations

- Investigate the parent process (`AutoIt.exe` or `dotnet.exe`) for signs of malicious activity.
- Analyze the command line and any referenced files for evidence of injection or payload delivery.
- Review network activity for potential C2 communications or payload downloads.
- Correlate with other endpoint alerts for lateral movement or privilege escalation.

---

## False Positives

False positives may occur if:

- Legitimate automation or deployment tools use `AutoIt.exe` or `dotnet.exe` to interact with `RegSvcs.exe`.
- Internal IT scripts or software installers perform similar actions for benign purposes.

---

## Recommended Response Actions

1. Isolate the affected endpoint to prevent further compromise.
2. Analyze the parent process and any associated scripts or executables.
3. Review process injection techniques and memory artifacts for malicious code.
4. Search for additional indicators of compromise (IOCs) across the environment.
5. Block or quarantine the identified files and processes.

---

## References

- [MITRE ATT&CK: T1055.003 – Process Injection](https://attack.mitre.org/techniques/T1055/003/)
- [MITRE ATT&CK: T1071.001 – Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [Cascading Shadows: An Attack Chain Approach to Avoid Detection and Complicate Analysis](https://unit42.paloaltonetworks.com/phishing-campaign-with-complex-attack-chain/#new_tab)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-29 | Initial Detection | Created hunt query to detect process injection into RegSvcs.exe by AutoIt or .NET executables |
