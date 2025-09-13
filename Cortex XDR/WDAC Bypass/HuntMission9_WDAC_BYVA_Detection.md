# Detection of Vulnerable Application Introduction and Exploitation (BYVA)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 89
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-BYVA
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects **Bring Your Own Vulnerable Application (BYVA)** techniques where attackers introduce vulnerable applications into an environment and exploit them to bypass WDAC.  

Detected behaviors include:

- Introduction of **new executables** (`.exe`, `.dll`, `.scr`) into **non-standard directories** (outside of Windows or Program Files).  
- **Suspicious activity** from typically benign applications (e.g., `notepad.exe`, `calc.exe`, `mspaint.exe`, `wordpad.exe`) when invoked with unusual command-line arguments such as `http`, `powershell`, or `cmd`.  
- Identification of applications that are **third-party signed** or not signed by Microsoft, potentially masking vulnerable loaders.  

By correlating **file introduction** with **suspicious process execution**, this hunt surfaces early indicators of WDAC bypass attempts using BYVA.

---

## ATT&CK Mapping

| Tactic                  | Technique   | Subtechnique | Technique Name                          |
|-------------------------|-------------|--------------|----------------------------------------|
| TA0005 - Defense Evasion| T1211       | -            | Exploitation for Defense Evasion        |
| TA0011 - Command & Control| T1105     | -            | Ingress Tool Transfer                   |

---

## Hunt Query Logic

The query combines **file write events** for new executables with **suspicious executions** of otherwise benign applications, surfacing **potential BYVA chains** where attackers import and abuse vulnerable binaries.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Title: Bring Your Own Vulnerable Application (BYVA) Detection 
// Description: Detects introduction of vulnerable applications for WDAC bypass 
// MITRE ATT&CK TTP ID: T1211, T1105

config case_sensitive = false  

| dataset = xdr_data  

| filter (event_type = ENUM.FILE and event_sub_type = ENUM.FILE_WRITE) or (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) 

| alter  
    new_executable = if(  
        event_type = ENUM.FILE and   
        action_file_name ~= ".*\.(exe|dll|scr)$" and  
        action_file_path not contains "\Windows\" and  
        action_file_path not contains "\Program Files\",  
        "New Binary", "Existing"  
    ),  
    vulnerable_indicators = if(  
        actor_process_image_name in (  
            "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe"  
        ) and (  
            actor_process_command_line contains "http" or  
            actor_process_command_line contains "powershell" or  
            actor_process_command_line contains "cmd"  
        ),  
        "Suspicious Activity", "Normal"  
    ),  
    third_party_signed = if(  
        actor_process_signature_vendor != "Microsoft Corporation" and  
        actor_process_signature_status != null,  
        "Third Party Signed", "Microsoft/Unsigned"  
    )  

| filter new_executable = "New Binary" or vulnerable_indicators = "Suspicious Activity"  

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line,  
         action_file_path, action_file_name, new_executable, vulnerable_indicators,  
         third_party_signed, actor_process_signature_vendor, actor_effective_username  

| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | File                | File Creation/Modification |
| Cortex XSIAM |    xdr_data      | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to copy binaries into non-system directories.  
- **Required Artifacts:** File system write logs, process creation events, digital signature validation.  

---

## Considerations

- BYVA attacks are particularly dangerous as they weaponize **legitimately signed vulnerable applications**.  
- Early detection requires analysis of both **file placement** and **suspicious usage patterns**.  
- Some benign applications may display **similar behavior during updates or testing**.  

---

## False Positives

False positives may occur from:  
- **Legitimate third-party application installations**.  
- Normal execution of productivity tools (e.g., Notepad, Paint) with benign parameters.  
- **Development and testing environments** introducing new binaries repeatedly.  

---

## Tuning Recommendations

- Integrate **application reputation checks** with external threat intelligence.  
- Correlate with **network context** to confirm if new binaries are sourced from suspicious IPs/domains.  
- Apply **time-based correlations** between binary introduction and unusual process execution.  

---

## Recommended Response Actions

1. Investigate new binary introductions in non-standard directories.  
2. Validate signatures of new applications and cross-check against threat intel.  
3. Review suspicious execution of benign Windows tools for **payload hosting or scripting patterns**.  
4. Hunt environment-wide for reuse of the same vulnerable application artifacts.  
5. Contain affected endpoints and restore trusted baselines if compromise is suspected.  

---

## References

- [MITRE ATT&CK: T1211 – Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)  
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)  
- [Microsoft: WDAC Policy Protections](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/wdac-and-applocker-overview)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | BYVA detection query combining file introduction and suspicious process usage. |
