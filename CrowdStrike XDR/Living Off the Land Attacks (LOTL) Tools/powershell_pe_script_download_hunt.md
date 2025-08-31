# Portable Executable or Script Download via PowerShell from Remote Destination Hunt Query Documentation

## Overview
This hunt query identifies portable executable (PE) or script files downloaded via PowerShell from remote destinations. It correlates process, network, and file events from the Falcon sensor to detect such downloads, which are often used by adversaries to transfer tools or malware into compromised environments.

---

## Hunt Query Logic

- Retrieves relevant events from the `base_sensor` repository on Windows endpoints, including process, DNS, and file write events.
- Correlates process IDs across event types to link PowerShell activity, DNS requests, and file writes.
- Excludes trusted domain names (e.g., Microsoft, Windows Update, Chocolatey, etc.) to reduce false positives.
- Focuses on new executable or script files written by PowerShell processes (`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`), excluding policy scripts.
- Groups results by agent, computer, local IP, and process ID, collecting file names, domain names, user names, and command lines for investigation.

---

## Hunt Query Syntax

**Query Language:** LogScale Query Language (Humio)  
**Platform:** LogScale (Humio)

```humio
#repo="base_sensor" event_platform="Win" 
| #event_simpleName =~ in(values=["NewExecutableWritten", "NewScriptWritten", "DnsRequest", "ProcessRollup2"]) 
| #event_simpleName match { 
    ProcessRollup2 => falcon_pid := TargetProcessId; 
    * => falcon_pid := ContextProcessId;     
} 
| selfJoinFilter([aid, falcon_pid], 
    where=[ 
        { #event_simpleName="ProcessRollup2" UserSid!="S-1-5-18" }, 
        // Modify the rule to exclude additional trusted domain names specific to your environment. 
        { #event_simpleName="DnsRequest" | DomainName =~ !in(values=["*.microsoft.com", "*.azureedge.net", "*.powershellgallery.com", "*.windowsupdate.com", "dist.nuget.org", "*.digicert.com", "*.princeton.edu", "princeton.service-now.com", "packages.chocolatey.org", 
"graph.windows.net" ,"autologon.microsoftazuread-sso.com","login.microsoftonline.com", "outlook.office365.com", "dc.services.visualstudio.com", "*.azure.com", "prdpuemailopsst.queue.core.windows.net", "*.princeton.edu.", "ci.dot.net"]) }, 
        { #event_simpleName =~ in(values=["NewExecutableWritten", "NewScriptWritten"]) | FileName!= "__PSScriptPolicy*.ps1" | ContextBaseFileName =~ in(values=["powershell.exe", "pwsh.exe", "powershell_ise.exe"], ignoreCase=true) } 
    ], prefilter=true 
) 
| groupBy([aid, ComputerName, LocalIP, falcon_pid],  
    function=[ 
        collect([TargetFileName, DomainName, UserName, CommandLine]) 
    ] 
) 
| TargetFileName=* DomainName=* CommandLine=*
```

---

## Data Sources

| Log Provider | Event Name              | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|-------------------------|---------------------|------------------------|
| Falcon       | NewExecutableWritten    | File                | File Creation          |
| Falcon       | NewScriptWritten        | File                | File Creation          |
| Falcon       | DnsRequest              | Network             | DNS Query              |
| Falcon       | ProcessRollup2          | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process, network, and file creation events from Windows endpoints.
- **Required Artifacts:** Process execution logs, DNS requests, file write events.

---

## Considerations

- Review the list of excluded trusted domains and tune for your environment to reduce false positives.
- Investigate the context of the PowerShell command line, the downloaded file, and the associated domain.
- Correlate with other suspicious behaviors, such as lateral movement or privilege escalation.

---

## False Positives

False positives may occur if:
- Legitimate automation or deployment tools use PowerShell to download files from trusted or internal sources not included in the exclusion list.
- Internal IT scripts or software distribution systems use PowerShell for benign downloads.

---

## Recommended Response Actions

1. Investigate the downloaded file and its source domain.
2. Validate the legitimacy of the PowerShell command and the user context.
3. Review related process activity and network connections.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [LOLBAS: PowerShell](https://lolbas-project.github.io/lolbas/Scripts/Powershell/)
- [CrowdStrike: Detecting Malicious PowerShell Usage](https://www.crowdstrike.com/blog/detecting-malicious-powershell-usage/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect PE or script downloads via PowerShell from remote destinations |
