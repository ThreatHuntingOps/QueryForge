
# Detection of AMSI Bypass Attempts via PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AMSIBypassDetection
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt identifies PowerShell-based attempts to bypass AMSI (Anti-Malware Scan Interface), a critical Windows security feature that enables real-time inspection of scripts and commands. Malicious actors, including Lumma Stealer operators, often use AMSI bypass techniques to evade detection and execute obfuscated or encrypted code.

Key indicators of AMSI bypass attempts include:

- Usage of `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`
- Setting `amsiInitFailed` to `true`
- Obfuscation via known keywords such as `Invoke-Metasploit` or `AMSI_RESULT_NOT_DETECTED`

This technique is a strong signal of malicious intent, especially in post-exploitation scenarios involving credential theft or malware loading.

---

## ATT&CK Mapping

| Tactic                     | Technique    | Subtechnique | Technique Name                              |
|---------------------------|--------------|---------------|---------------------------------------------|
| TA0005 - Defense Evasion  | T1562.001    | —             | Impair Defenses: Disable or Modify Tools    |
| TA0002 - Execution        | T1203        | —             | Exploitation for Client Execution           |
| TA0005 - Defense Evasion  | T1027        | —             | Obfuscated Files or Information             |

---

## Hunt Query Logic

This query captures suspicious PowerShell or PowerShell Core (`pwsh.exe`) executions that attempt to disable AMSI or evade its detection.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 
| in(field="FileName", values=["powershell.exe", "pwsh.exe"]) 
| in(field="CommandLine", values=["*[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')*", "*amsiInitFailed*", "*AMSI_RESULT_NOT_DETECTED*", "*Invoke-Metasploit*", "*System.Management.Automation.AmsiUtils*"]) 
```

---

## Data Sources

| Log Provider | Event ID | Event Name     | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|----------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2 | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to run PowerShell with command-line arguments.
- **Required Artifacts:** Script execution traces, command-line logs.

---

## Considerations

- Correlate execution context with user activity and timeline.
- Examine script origin and integrity.
- Look for additional signs of payload decryption or injection.

---

## False Positives

False positives may arise from:

- Legitimate administrative scripts interacting with `AmsiUtils` for debugging or compatibility reasons.
- Security tools testing AMSI bypass techniques for red teaming or detection validation.

---

## Recommended Response Actions

1. Capture the full PowerShell script for analysis.
2. Investigate the process tree to determine parent and child relationships.
3. Check for persistence mechanisms or downloaded payloads.
4. Isolate the endpoint if malicious intent is confirmed.
5. Apply behavioral detection tuning to reduce FPs.

---

## References

- [MITRE ATT&CK: T1562.001 – Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK: T1203 – Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Microsoft: Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [Lumma Stealer – Tracking distribution channels](https://securelist.com/lumma-fake-captcha-attacks-analysis/116274/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                   |
|---------|------------|-------------------|-----------------------------------------------------------------------------------------|
| 1.0     | 2025-04-25 | Initial Detection | Created hunt query to detect AMSI bypass attempts leveraging PowerShell command patterns |
