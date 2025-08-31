# Suspicious Remote Monitoring and Management (RMM) Tool Usage Indicative of Threat Actor Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RMMAbuse
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious executions of Remote Monitoring and Management (RMM) tools, which are increasingly abused by cybercriminals. RMM software, typically used by IT professionals for legitimate system management, is leveraged by threat actors to gain unauthorized access, deploy malware, steal sensitive data, and maintain persistent control over compromised systems. Detected behaviors include:

- Execution of known RMM binaries on endpoints
- Unusual or unexpected RMM tool usage across multiple systems
- Aggregation of execution events to identify lateral movement or mass deployment
- Potential for ransomware deployment, credential harvesting, and stealthy persistence

Such activity is often associated with post-exploitation, initial access, and hands-on-keyboard attacks.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                            |
|------------------------------|------------|---------------|-----------------------------------------------------------|
| TA0002 - Execution            | T1569.002 | —             | System Services: Service Execution                        |
| TA0003 - Persistence          | T1136     | —             | Create Account                                            |
| TA0008 - Lateral Movement     | T1021.001 | —             | Remote Services: Remote Desktop Protocol                  |
| TA0006 - Credential Access    | T1555     | —             | Credentials from Password Stores                          |
| TA0007 - Discovery            | T1082     | —             | System Information Discovery                              |
| TA0011 - Command and Control  | T1219     | —             | Remote Access Software                                    |

---

## Hunt Query Logic

This query identifies suspicious RMM tool executions by:

- Matching process execution events against a curated list of known RMM binaries
- Aggregating by RMM program name, endpoint, and execution count
- Highlighting unexpected or widespread use of RMM tools
- Generating detection logic for custom indicators of attack (IOA) based on observed binaries

A secondary query hunts for executions of specific RMM binaries, grouping by file path and hash, and flags cases where the tool is seen on a limited number of endpoints (potentially indicating targeted abuse).

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Get all Windows process execution events
#event_simpleName=ProcessRollup2 event_platform=Win

// Check to see if FileName value matches the value or a known RMM tools as specified by our lookup file
| match(file="rmm_list.csv", field=[FileName], column=rmm_binary, ignoreCase=true)

// Do some light formatting
| regex("(?<short_binary_name>\w+)\.exe", field=FileName)
| short_binary_name:=lower("short_binary_name")
| rmm_binary:=lower(rmm_binary)

// Aggregate by RMM program name
| groupBy([rmm_program], function=([
    collect([rmm_binary]),  
    collect([short_binary_name], separator="|"),   
    count(FileName, distinct=true, as=FileCount),  
    count(aid, distinct=true, as=EndpointCount),  
    count(aid, as=ExecutionCount)
]))

// Create case statement to display what Custom IOA regex will look like
| case{
    FileCount>1 | ImageFileName_Regex:=format(format=".*\\(%s)\.exe", field=[short_binary_name]);
    FileCount=1 | ImageFileName_Regex:=format(format=".*\\%s\.exe", field=[short_binary_name]);
}

// More formatting
| description:=format(format="Unexpected use of %s observed. Please investigate.", field=[rmm_program])
| rename([[rmm_program,RuleName],[rmm_binary,BinaryCoverage]])
| table([RuleName, EndpointCount, ExecutionCount, description, ImageFileName_Regex, BinaryCoverage], sortby=ExecutionCount, order=desc)
```

**Alternate Query:**

```fql
// RMM Tool Hunting
#event_simpleName=ProcessRollup2 event_platform=Win

// Add in additional program names here. 
| in(field="FileName", values=[anydesk.exe, AteraAgent.exe, teamviewer.exe, SRService.exe, SRManager.exe, SRServer.exe, SRAgent.exe, ClientService.exe, "ScreenConnect.WindowsClient.exe", ngrok.exe], ignoreCase=true) 
| FilePath=/\\Device\\HarddiskVolume\d\\(?<ShortFilePath>.+$)/ 
| groupBy([FileName, ShortFilePath, SHA256HashData], function=([count(aid, as=TotalExecutions), count(aid, distinct=true, as=UniqueEndpoints), collect([ComputerName])])) 
// Adjust threshold 
| UniqueEndpoints<15 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute RMM binaries on endpoints.
- **Required Artifacts:** RMM binary files, process execution logs, endpoint inventory.

---

## Considerations

- Validate if RMM tool usage is authorized and expected for the endpoint or user.
- Investigate the source and integrity of the RMM binary (hash, path, signature).
- Review for signs of lateral movement, mass deployment, or privilege escalation.
- Correlate with other suspicious activity (e.g., ransomware, credential access, persistence).

---

## False Positives

False positives may occur if:

- IT administrators are legitimately deploying or using RMM tools for support or maintenance.
- Automated software deployment or patching systems utilize RMM binaries.
- Security or compliance testing involves RMM tool execution.

---

## Recommended Response Actions

1. Investigate the context of RMM tool execution (user, time, endpoint).
2. Validate the legitimacy of the RMM binary and its source.
3. Review endpoint activity for signs of compromise or lateral movement.
4. Isolate affected systems if unauthorized RMM usage is confirmed.
5. Remove unauthorized RMM tools and reset credentials as needed.

---

## References

- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [Hunting Windows RMM Tools](https://www.reddit.com/r/crowdstrike/comments/1gb30r9/20241024_cool_query_friday_part_ii_hunting/?share_id=FMJ9rRNfpuMFTW7OfhC83&utm_content=2&utm_medium=android_app&utm_name=androidcss&utm_source=share&utm_term=2)
- [Detecting RMMs](https://blog.nviso.eu/2024/10/21/hunting-for-remote-management-tools-detecting-rmms/)
- [Cool Query Friday - Hunting Windows RMM Tools](https://www.reddit.com/r/crowdstrike/comments/1g6iupi/20241018_cool_query_friday_hunting_windows_rmm/)
- [rmm_executables_list](https://raw.githubusercontent.com/CrowdStrike/logscale-community-content/refs/heads/main/Misc/rmm_executables_list.csv)
- [Threat hunting case study: RMM software](https://intel471.com/blog/threat-hunting-case-study-rmm-software?utm_content=327770375&utm_medium=social&utm_source=linkedin&hss_channel=lcp-3744600)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect suspicious RMM tool usage and potential threat actor activity  |
