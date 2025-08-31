# Detection of Suspicious DLL-Based Loader Execution Linked to Game

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-YouieLoadDLL
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious command-line patterns and image file names consistent with the YouieLoad malware loader. YouieLoad is a DLL-based loader that is loaded in memory alongside a game executable to execute additional malicious payloads. The detection logic focuses on command lines referencing both `--game` and a DLL, as well as image file names or command lines referencing `YouieLoad.dll`.

Such behavior is indicative of process injection, proxy execution, and obfuscation techniques, where attackers use DLL loaders to stealthily execute malware in the context of legitimate game processes.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0005 - Defense Evasion     | T1055.012   | —            | Process Injection: Process Hollowing                   |
| TA0002 - Execution           | T1218.011   | —            | Signed Binary Proxy Execution: Rundll32                |
| TA0005 - Defense Evasion     | T1027       | —            | Obfuscated Files or Information                        |

---

## Hunt Query Logic

This query identifies suspicious DLL-based loader executions by detecting:

- Command lines containing both `--game` and a DLL reference
- Image file names or command lines referencing `YouieLoad.dll` or `YouieLoad`

These patterns are commonly seen in attacks where DLL loaders are used to inject or execute additional payloads in the context of game processes.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (CommandLine = "*--game*" AND CommandLine = "*.dll")  
| (ImageFileName = "*YouieLoad.dll*" OR CommandLine = "*YouieLoad*")   
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute DLLs and supply custom command-line arguments.
- **Required Artifacts:** Process creation logs, command-line arguments, DLL file information.

---

## Considerations

- Validate the legitimacy of the detected DLL and its association with the game process.
- Investigate the referenced DLL for signs of tampering or malicious payloads.
- Correlate with other endpoint or network alerts for process injection or obfuscation activity.

---

## False Positives

False positives may occur if:

- Legitimate game launchers use DLL loaders with similar command-line patterns.
- System administrators or automation tools invoke DLLs with custom arguments for valid reasons.
- Security testing or red team activities mimic these behaviors.

---

## Recommended Response Actions

1. Review and validate the legitimacy of the detected DLL loader and its command-line usage.
2. Analyze the referenced DLL for malicious content or process hollowing behavior.
3. Investigate user and process activity around the time of execution.
4. Remove unauthorized DLL loaders or payloads if confirmed malicious.
5. Update detection rules and threat intelligence with new indicators as needed.

---

## References

- [MITRE ATT&CK: T1055.012 – Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK: T1218.011 – Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks (Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-09 | Initial Detection | Created hunt query to detect suspicious DLL-based loader execution linked to game           |
