# Detection of SplitLoader DLL Execution Through LOLBins

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-SplitLoaderDLL-LOLBins
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious execution of `SplitLoader.dll`, a DLL associated with stage 2/3 payload delivery in Moonstone Sleet’s multi-stage attack chain. The detection focuses on the use of Living-off-the-Land Binaries (LOLBins) such as `rundll32.exe` or `regsvr32.exe` to launch the DLL, a common technique for stealthy malware execution and defense evasion.

Such behavior is indicative of advanced threat activity, including process injection and proxy execution, and is often used to bypass security controls by leveraging trusted Windows binaries.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1218.011   | —            | Signed Binary Proxy Execution: Rundll32                |
| TA0002 - Execution           | T1218.010   | —            | Signed Binary Proxy Execution: Regsvr32                |
| TA0005 - Defense Evasion     | T1055.001   | —            | Process Injection: Dynamic-link Library Injection      |

---

## Hunt Query Logic

This query identifies suspicious executions where `SplitLoader.dll` is loaded via LOLBins:

- The process references `SplitLoader.dll` in its file name
- The command line includes either `rundll32` or `regsvr32`

These patterns are commonly seen in advanced multi-stage attacks leveraging trusted Windows binaries for stealthy DLL execution.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| FileName = /SplitLoader\.dll/i  
| (CommandLine = "*rundll32*" OR CommandLine = "*regsvr32*")   
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute DLLs via LOLBins.
- **Required Artifacts:** Process creation logs, command-line arguments, DLL file information.

---

## Considerations

- Validate the signature and hash of the detected `SplitLoader.dll`.
- Investigate the parent process and user context for signs of lateral movement or privilege escalation.
- Correlate with other endpoint or network alerts for multi-stage attack activity.

---

## False Positives

False positives may occur if:

- Legitimate software uses DLLs named `SplitLoader.dll` for benign purposes.
- System administrators or automation scripts use LOLBins for valid DLL registration or execution.
- Security testing or red team activities mimic these behaviors.

---

## Recommended Response Actions

1. Isolate the affected endpoint if malicious activity is confirmed.
2. Analyze the suspicious DLL for tampering or embedded payloads.
3. Review user and process activity around the time of execution.
4. Investigate for signs of process injection or privilege escalation.
5. Update detection rules and threat intelligence with new indicators as needed.

---

## References

- [MITRE ATT&CK: T1055.001 – Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)
- [MITRE ATT&CK: T1218.011 – Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK: T1218.010 – Signed Binary Proxy Execution: Regsvr32](https://attack.mitre.org/techniques/T1218/010/)
- [Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks (Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-09 | Initial Detection | Created hunt query to detect SplitLoader DLL execution via LOLBins                          |
