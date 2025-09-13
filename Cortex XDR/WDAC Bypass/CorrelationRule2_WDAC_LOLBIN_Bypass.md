# WDAC Bypass - Suspicious LOLBIN Execution with Process Ancestry Anomalies

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Analytics Metadata

- **ID:** CorrelationRule-Windows-WDAC-LOLBIN-Bypass
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Analytics

This correlation rule detects **WDAC bypass attempts** by chaining together multiple suspicious signals. The detection is based on:  

- **Stage 1:** Execution of Known LOLBINs (`msbuild.exe`, `InstallUtil.exe`, `wmic.exe`, `regsvr32.exe`, `rundll32.exe`, etc.).  
- **Stage 2:** Suspicious parent-child process ancestry anomalies, such as LOLBINs spawned by Office applications or browsers, or LOLBIN invocation using files from **Temp, Downloads, AppData, or network paths (http/ftp)**.  
- **Stage 3:** Suspicious command-line patterns indicative of abuse, including embedded PowerShell, CMD execution, Base64 payloads, task injection (`<Task>`), inline scripts, XSL, or HTA abuse.  

Only when all **three stages** align does this rule generate an alert, reducing false positives and providing **high-confidence detection** of WDAC bypass attempts via LOLBIN abuse.

---

## ATT&CK Mapping

| Tactic                         | Technique   | Subtechnique | Technique Name                             |
|--------------------------------|-------------|--------------|-------------------------------------------|
| TA0005 - Defense Evasion       | T1218       | -            | System Binary Proxy Execution: LOLBins    |
| TA0005 - Defense Evasion       | T1055       | -            | Process Injection                         |
| TA0002 - Execution             | T1059       | T1059.001    | Command and Scripting Interpreter: PowerShell |

---

## Query Logic

The correlation looks for **LOLBIN execution paired with abnormal ancestry and malicious command-line indicators**. Detection requires all three stages:  

- LOLBIN execution  
- Suspicious ancestry  
- Suspicious command-line pattern  

This ensures fidelity over individual LOLBIN execution detections.

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
config case_sensitive = false
| dataset = xdr_data

// Stage 1: LOLBIN Execution Detection
| alter lolbin_flag = if(
        event_type = PROCESS and
        actor_process_image_name in (
            "msbuild.exe","csi.exe","InstallUtil.exe","mshta.exe","wmic.exe",
            "cdb.exe","windbg.exe","dbghost.exe","dotnet.exe","fsi.exe",
            "Microsoft.Workflow.Compiler.exe","rcsi.exe","runscripthelper.exe",
            "regsvr32.exe","rundll32.exe","cmstp.exe"
        ),
        true,false
  )

// Stage 2: Process Ancestry Anomalies
| alter ancestry_flag = if(
        lolbin_flag = true and (
          causality_actor_process_image_name in ("winword.exe","excel.exe","powerpnt.exe","outlook.exe",
                                                 "chrome.exe","firefox.exe","msedge.exe","iexplore.exe")
          or actor_process_command_line contains "Temp"
          or actor_process_command_line contains "Downloads"
          or actor_process_command_line contains "AppData"
          or actor_process_command_line contains "http"
          or actor_process_command_line contains "ftp"
        ),
        true,false
  )

// Stage 3: Command-Line Suspicious Pattern Detection
| alter pattern_flag = if(
        ancestry_flag = true and (
            actor_process_command_line contains "/c "
            or actor_process_command_line contains "powershell"
            or actor_process_command_line contains "cmd.exe"
            or actor_process_command_line contains "base64"
            or actor_process_command_line contains "/u "
            or actor_process_command_line contains "<Task>"
            or actor_process_command_line contains "inline"
            or actor_process_command_line contains ".xsl"
            or actor_process_command_line contains ".hta"
        ),
        true,false
  )

// Correlation
| filter lolbin_flag = true and ancestry_flag = true and pattern_flag = true
```

---

## Data Sources

| Log Provider   | Event Name  | ATT&CK Data Source  | ATT&CK Data Component  |
|----------------|-------------|---------------------|------------------------|
| Cortex XSIAM   | xdr_data    | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User-level file execution; administrative for persistence.  
- **Required Artifacts:** Process creation logs with command-line arguments.  

---

## Considerations

- Correlating ancestry and command-line suspicious indicators increases reliability.  
- Single LOLBIN execution is not automatically malicious; correlation is key.  
- Threat actors often chain LOLBIN + network + PowerShell for WDAC bypass.  

---

## False Positives

False positives may occur if:  
- Developers, administrators, or IT tools use LOLBINs in automation.  
- Legitimate Office applications invoke LOLBINs for add-ons or macros.  

---

## Recommended Response Actions

1. Immediately review the command-line arguments.  
2. Investigate parent/child relationships of LOLBIN execution.  
3. Contain endpoint if LOLBIN executed from **Temp, AppData, Downloads**.  
4. Check for persistence using malicious tasks or registry modifications.  
5. Hunt across environment for similar suspicious LOLBIN activity.  

---

## References

- [MITRE ATT&CK: T1218 – System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)  
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)  
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                      |
|---------|------------|-------------------|------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Added correlation to detect LOLBIN-based WDAC bypass.      |
