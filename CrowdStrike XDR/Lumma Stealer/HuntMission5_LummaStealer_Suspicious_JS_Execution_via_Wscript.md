# Detection of Suspicious JavaScript Execution via wscript.exe

## Metadata
**ID:** HuntQuery-CrowdStrike-LummaStealer-Suspicious-JS-Execution-via-Wscript  
**OS:** WindowsEndpoint, WindowsServer  
**FP Rate:** Medium  

---

## ATT&CK Tags

| Tactic                | Technique | Subtechnique | Technique Name                               |
|----------------------|-----------|---------------|----------------------------------------------|
| TA0002 - Execution    | T1059     | 007           | Command and Scripting Interpreter: JavaScript |
| TA0001 - Initial Access | T1566   | 002           | Phishing: Spearphishing via Service          |
| TA0002 - Execution    | T1204     | 002           | User Execution: Malicious File               |

---

## Utilized Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source | ATT&CK Data Component |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Execution      |

---

## Technical description of the attack
This hunt is designed to detect a common delivery method for malicious JavaScript used in phishing campaigns impersonating Chrome browser updates. The malware is typically downloaded through deceptive websites and stored in the user’s `Downloads` directory. The script is then executed using `wscript.exe`, with `chrome.exe` as the parent process—an indicator of a fake Chrome update attack vector.

---

## Permission required to execute the technique
User

---

## Detection description
This query hunts for JavaScript executions by `wscript.exe` originating from a download directory and triggered by a parent process named `chrome.exe`. This behavior mimics known techniques used in social engineering campaigns where users are lured into downloading and executing disguised malware.

---

## Considerations
Additional fields such as `ProcessCommandLine`, `InitiatingProcessId`, `UserSid`, and `FolderPath` should be used for deeper context during investigation. Ensure proper tuning by excluding legitimate administrative scripts and internal automation tools.

---

## False Positives
Legitimate scripts, especially those related to enterprise software installations or automation tasks, may match this pattern. Analysts should validate the file origin, user intent, and execution context before escalating.

---

## Suggested Response Actions
- Isolate affected endpoint to prevent further spread.
- Analyze the script file and identify any malicious payloads or communications.
- Trace the origin site and determine the full infection chain.
- Educate the user on the dangers of fake browser update prompts.
- Block and report associated domains or URLs involved in the lure.

---

## References
* [MITRE ATT&CK - T1059.007](https://attack.mitre.org/techniques/T1059/007/)
* [MITRE ATT&CK - T1204.002](https://attack.mitre.org/techniques/T1204/002/)
* [MITRE ATT&CK - T1566.002](https://attack.mitre.org/techniques/T1566/002/)
* [Threat actors using fake Chrome updates to deliver Lumma Stealer](https://security.microsoft.com/threatanalytics3/4aa69db9-9f04-46ca-b07f-c67f7105f61d/analystreport?tid=2ff60116-7431-425d-b5af-077d7791bda4&si_retry=1)

---

## Detection

**Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2
| (ImageFileName=/wscript\.exe/i OR CommandLine=*wscript.exe*)
| CommandLine=*CanaryUpdate* OR CommandLine=*.js
| (CommandLine=*\\Downloads\\* OR CommandLine=*C:\\Users\\*\\Downloads\\*)
| ParentBaseFileName=chrome.exe
```

---
## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2025-04-13| Initial Detection | Created hunt query to detect fake Chrome update lures executing via wscript.exe |
