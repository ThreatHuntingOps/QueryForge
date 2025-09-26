# AdaptixC2 Reconnaissance Command Sequence Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80 (multi-tool reconnaissance from PowerShell parent)  
- **Severity:** Medium–High  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-AdaptixC2-Recon-Sequence  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium-Low (sequence of multiple native tools parented by PowerShell is suspicious)  

---

## Analytics

This correlation rule detects **reconnaissance activity executed by AdaptixC2** leveraging PowerShell-spawned enumeration commands.  

Detected behaviors include:  
- **Parent process PowerShell.exe** initiating system/domain reconnaissance tools.  
- **Multiple sequential invocations** of reconnaissance utilities.  
- **System and network discovery** via native tools.  

Common recon utilities used by AdaptixC2:  
- `ipconfig.exe` → Collect network configuration.  
- `whoami.exe` → Identify active user/account.  
- `nltest.exe` → Enumerate domain trusts and connectivity.  
- `net.exe` → Enumerate shares, sessions, accounts.  
- `systeminfo.exe` → Gather system/OS information.  

Detection requires **≥2 tool invocations within the same PowerShell process tree and timeframe**, ensuring correlation beyond single benign execution.

---

## ATT&CK Mapping

| Tactic       | Technique | Subtechnique | Technique Name                       |
|--------------|-----------|--------------|--------------------------------------|
| Discovery    | T1057     | -            | Process Discovery                    |
| Discovery    | T1082     | -            | System Information Discovery         |
| Discovery    | T1016     | -            | System Network Configuration (ipconfig) |
| Discovery    | T1033     | -            | System Owner/User Discovery (whoami) |
| Discovery    | T1482     | -            | Domain Trust Discovery (nltest)      |

---

## Query Logic

This analytic correlates **multiple reconnaissance commands spawned from PowerShell**.  
It prioritizes detections when ≥2 reconnaissance utilities execute on the same host within the same execution context.

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
config case_sensitive = false  
| dataset = xdr_data  
| filter event_type = PROCESS and event_sub_type = ENUM.PROCESS_START  
| filter causality_actor_process_image_name ~= "powershell.exe"  
| filter actor_process_image_name in ("ipconfig.exe", "whoami.exe", "nltest.exe", "net.exe", "systeminfo.exe")  
| alter detection_name = "AdaptixC2 Reconnaissance Sequence",  
       attack_technique = "T1057/T1082 - Discovery",  
       parent_process = causality_actor_process_image_name  
| comp count() as tool_count by agent_hostname, causality_actor_process_image_name, _time  
| filter tool_count >= 2  
| fields _time, agent_hostname, causality_actor_process_image_name, tool_count 
| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements  
- **Required Permissions:** User-level sufficient.  
- **Required Artifacts:** Process telemetry including parent-child relationships.  

---

## Considerations  
- Recon via PowerShell parent typically indicates malicious intent.  
- Admins may occasionally run such commands, but ≥2 sequential recon tools in one branch is rare outside red-team activity.  

---

## False Positives  
- Possible if administrators/scripts run multiple diagnostic tools quickly under PowerShell.  
- Tunable by requiring more than 2 recon tools or excluding trusted admin accounts.  

---

## Recommended Response Actions  
1. **Investigate parent PowerShell command line** for suspicious activity.  
2. **Correlate reconnaissance with subsequent lateral movement attempts.**  
3. **Isolate system** if reconnaissance attempts align with other AdaptixC2 detection signals.  
4. **Collect forensic artifacts** (PowerShell logs, Sysmon, registry, memory).  
5. **Hunt for additional reconnaissance chains** across enterprise environment.  

---

## References  
- [MITRE ATT&CK: T1057 – Process Discovery](https://attack.mitre.org/techniques/T1057/)  
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)  
- [MITRE ATT&CK: T1016 – System Network Configuration](https://attack.mitre.org/techniques/T1016/)  
- [MITRE ATT&CK: T1033 – System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)  
- [MITRE ATT&CK: T1482 – Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
  
---

## Version History  

| Version | Date       | Impact                         | Notes                                                             |
|---------|------------|--------------------------------|-------------------------------------------------------------------|
| 1.0     | 2025-09-26 | Initial Detection Contribution | Added correlation for AdaptixC2 reconnaissance PowerShell sequences |
