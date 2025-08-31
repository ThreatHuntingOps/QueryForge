# Detection of Suspicious AutoIt Dropper Execution (Potential Malware Delivery)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AutoIt-Dropper-API
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects execution of AutoIt-compiled executables that invoke sensitive Windows API functions commonly abused by malware, such as `VirtualProtect`, `CallWindowProc`, `DllStructCreate`, `DllStructSetData`, and `DllStructGetPtr`. These behaviors are indicative of shellcode injection and execution, aligning with the techniques used by AutoIt droppers to deliver and run malicious payloads (e.g., DarkCloud Stealer).

Detected behaviors include:

- Execution of AutoIt-compiled executables
- Invocation of Windows API functions associated with memory manipulation and code injection
- Correlation of process execution and API calls on the same host and process

Such techniques are often associated with advanced malware delivery and in-memory payload execution.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                             |
|------------------------------|--------------|--------------|-----------------------------------------------------------|
| TA0002 - Execution           | T1059.005    | —            | Command and Scripting Interpreter: AutoIt                 |
| TA0005 - Defense Evasion     | T1027        | —            | Obfuscated Files or Information                           |
| TA0004 - Privilege Escalation| T1055.001    | —            | Process Injection: Dynamic-link Library Injection         |

---

## Hunt Query Logic

This query identifies:

- **AutoIt Execution:** Execution of AutoIt-compiled executables.
- **Sensitive API Calls:** Invocation of suspicious Windows API functions indicative of shellcode injection and execution (e.g., VirtualProtect, CallWindowProc, DllStructCreate, DllStructSetData, DllStructGetPtr).
- **Joins:** Correlates AutoIt execution with suspicious API calls by matching agent ID (aid) and process ID (TargetProcessId).

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Detect suspicious AutoIt executables invoking sensitive Windows API functions

#event_simpleName="ProcessRollup2" 
| ImageFileName=/autoit.*\.exe/i OR CommandLine=/autoit.*\.exe/i 
| join( 
    {#event_simpleName="SyntheticProcessRollup2" 
     | CommandLine=/VirtualProtect|CallWindowProc|DllStructCreate|DllStructSetData|DllStructGetPtr/i 
    } 
    , field=TargetProcessId 
    , key=TargetProcessId 
    , include=[CommandLine] 
) 
| groupBy([aid, ComputerName], limit=max, function=collect([ImageFileName, CommandLine])) 
```

---

## Data Sources

| Log Provider | Event ID               | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A                    | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A                    | SyntheticProcessRollup2| Process             | API Call               |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute AutoIt-compiled executables.
- **Required Artifacts:** Process execution logs, API call telemetry.

---

## Considerations

- Investigate the source and legitimacy of AutoIt-compiled executables.
- Analyze command-line arguments and process ancestry for signs of obfuscation or malicious intent.
- Review API call patterns for evidence of memory manipulation or code injection.
- Correlate activity with known malware indicators or threat intelligence.

---

## False Positives

False positives may occur if:

- Legitimate AutoIt scripts invoke sensitive API functions for benign automation or system management tasks.
- Internal tools or automation leverage similar techniques for legitimate purposes.

---

## Recommended Response Actions

1. Investigate the executed AutoIt-compiled executables and their origin.
2. Analyze command-line arguments and process ancestry for suspicious behavior.
3. Review API call telemetry for evidence of shellcode injection or in-memory payload execution.
4. Monitor for additional signs of compromise or lateral movement.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [Unit 42: DarkCloud Stealer and Obfuscated AutoIt Scripting](https://unit42.paloaltonetworks.com/darkcloud-stealer-and-obfuscated-autoit-scripting/)
- [MITRE ATT&CK: T1059.005 – Command and Scripting Interpreter: AutoIt](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: T1055.001 – Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-19 | Initial Detection | Created hunt query to detect suspicious AutoIt dropper execution invoking sensitive Windows API functions |
