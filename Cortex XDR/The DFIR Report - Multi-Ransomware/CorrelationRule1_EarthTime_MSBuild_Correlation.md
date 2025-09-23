# EarthTime.exe Execution and Suspicious MSBuild.exe Usage

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (EarthTime execution observed)  
- **Severity:** High to Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-EarthTime-MSBuild
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low  

---

## Analytics

This correlation rule detects **initial access and defense evasion activity** leveraging a malicious binary masquerading as **EarthTime.exe** and suspicious execution of **MSBuild.exe** without arguments.  

Detected behaviors include:  

- **Malicious loader execution** (`EarthTime.exe`) disguised as a legitimate DeskSoft EarthTime application.  
- **Suspicious MSBuild abuse** – execution without arguments, inconsistent with normal MSBuild functionality.  
- **Living-off-the-Land Binary (LOLBin) usage** – MSBuild exploited to launch arbitrary code under a trusted Microsoft process.  
- **Follow-on C2 traffic** from MSBuild to suspicious IPs and ports, corroborating its use as a proxy for malicious communications.  

The rule correlates **process execution with anomalous network activity**, ensuring high-confidence detection of this initial vector.

---

## ATT&CK Mapping

| Tactic            | Technique | Subtechnique | Technique Name                             |
|-------------------|-----------|--------------|-------------------------------------------|
| Initial Access    | T1566     | T1566.001    | Phishing: Spearphishing Attachment        |
| Defense Evasion   | T1218     | T1218.001    | Signed Binary Proxy Execution: MSBuild    |
| Defense Evasion   | T1036     | T1036.005    | Masquerading: Match Legitimate Name/Loc.  |
| Command & Control | T1071     | T1071.001    | Application Layer Protocol: Web Protocols |

---

## Query Logic

This rule correlates **EarthTime.exe execution** or **MSBuild abuse with subsequent suspicious network activity**. The correlation filter ensures both process-based anomalies and supporting network behaviors align before flagging.

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM 

```xql
// Hunt for EarthTime.exe execution and suspicious MSBuild.exe usage
config case_sensitive = false  
| dataset = xdr_data  
| filter event_type in (PROCESS, NETWORK) 

// Phase 1: Detect EarthTime.exe execution 
| alter earthtime_execution = if( 
        event_type = PROCESS and actor_process_image_name contains "earthtime.exe", 
        true, false 
  ) 

// Phase 2: Detect suspicious MSBuild usage (runs with no arguments) 
| alter suspicious_msbuild = if( 
        event_type = PROCESS and actor_process_image_name contains "msbuild.exe" and 
        (actor_process_command_line = "" or actor_process_command_line = null or actor_process_command_line ~= ".*msbuild\.exe\s*$"), 
        true, false 
  ) 

// Phase 3: Detect MSBuild network connections to suspicious infrastructure 
| alter msbuild_network = if( 
        event_type = NETWORK and 
        causality_actor_process_image_name contains "msbuild.exe" and 
        (dst_action_external_port in (9000, 15647) or dst_actor_remote_ip contains "45.141.87.55"), 
        true, false 
  ) 

// Correlation Filter: require EarthTime or MSBuild execution + network 
| filter earthtime_execution = true 
   or (suspicious_msbuild = true and msbuild_network = true) 

// Enrichment 
| alter detection_category = if(earthtime_execution = true, "EarthTime Execution", 
                           if(suspicious_msbuild = true and msbuild_network = true, "MSBuild C2 Communication", 
                           "Generic Suspicious Activity")), 
       risk_score = if(earthtime_execution = true, 95, 
                  if(suspicious_msbuild = true and msbuild_network = true, 90, 
                  60)) 

// Output fields 
| fields _time, 
         agent_hostname, 
         actor_process_image_name, 
         actor_process_command_line, 
         causality_actor_process_image_name, 
         dst_action_external_port, 
         dst_actor_remote_ip, 
         detection_category, 
         risk_score, 
         event_type 

| sort desc risk_score, desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component       |
|----------------|------------|--------------------|-----------------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation            |
| Cortex XSIAM   | xdr_data   | Network            | Network Connection          |

---

## Execution Requirements

- **Required Permissions:** User-level sufficient; elevated not required for MSBuild abuse.  
- **Required Artifacts:** Process and network telemetry.  

---

## Considerations

- **EarthTime.exe execution** outside of legitimate install directories should be considered highly suspicious.  
- **MSBuild without arguments** is unusual, flagging anomalous execution patterns.  
- Detection correlates **binary masquerading with anomalous C2 behavior** for stronger attribution.  

---

## False Positives

- Rare but possible during legitimate testing of MSBuild.  
- Legitimate execution may appear unusual in lab environments.  

---

## Recommended Response Actions

1. **Isolate the endpoint** to prevent follow-on payload delivery.  
2. **Examine MSBuild process tree** for parent/child relationships and injected modules.  
3. **Analyze outbound traffic** to suspicious IPs or ports.  
4. **Acquire memory and volatile data** for forensic analysis.  
5. **Hunt for EarthTime.exe artifacts** across enterprise endpoints.  

---

## References

- [MITRE ATT&CK: T1218.001 – MSBuild Proxy Execution](https://attack.mitre.org/techniques/T1218/001/)  
- [MITRE ATT&CK: T1036.005 – Masquerading](https://attack.mitre.org/techniques/T1036/005/)  
- [MITRE ATT&CK: T1071.001 – C2 Web Protocols](https://attack.mitre.org/techniques/T1071/001/)  
- [MITRE ATT&CK: T1566.001 – Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)  

---

## Version History

| Version | Date       | Impact                  | Notes                                                                 |
|---------|------------|-------------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-18 | Initial Detection       | Added correlation for EarthTime.exe and MSBuild LOLBin abuse with C2. |
