# Detection of Suspicious mmap/mmap2 Usage in Fileless Malware (VShell Backdoor Behavior)

## Hunt Analytics Metadata

- **ID:** `HuntQuery-Linux-Fileless-mmap-Behavioral`
- **Operating Systems:** `LinuxEndpoint`, `LinuxServer`
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects behavioral indicators of fileless malware leveraging advanced memory allocation techniques on Linux, focusing on the VShell backdoor and similar threats. These implants use `mmap` and `mmap2` system calls with `MAP_PRIVATE | MAP_ANONYMOUS` flags and `fd=-1` to allocate large, anonymous memory regions (e.g., 64MB, 128MB, 512MB). Memory is often staged with `PROT_NONE` and later remapped with `PROT_EXEC` for payload injection, a pattern seen in sophisticated memory-resident malware.

Detection logic is based on behavioral patterns, not static IOCs, to identify stealthy, fileless malware activity. Key behaviors include:

- Command lines referencing `mmap` or `mmap2` system calls
- Use of `MAP_PRIVATE` and `MAP_ANONYMOUS` flags with `fd=-1`
- Memory regions staged with `PROT_NONE` and later with `PROT_EXEC`
- Large memory allocations (64MB, 128MB, 512MB)
- Process or file names such as `memfd.*` or masquerading as `kworker*`

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                                      |
| TA0005 - Defense Evasion     | T1055.012   | —            | memfd_create Injection Technique                       |
| TA0005 - Defense Evasion     | T1027.002   | —            | Obfuscated Files or Information: Gobfuscate            |
| TA0002 - Execution           | T1106       | —            | Native API Execution (e.g., mmap, fexecve)             |
| TA0006 - Credential Access   | T1497.001   | —            | Virtualization/Sandbox Evasion: Delayed Execution      |
| TA0002 - Execution           | T1203       | —            | Exploitation for Client Execution                      |

---

## Hunt Query Logic

This query identifies suspicious memory allocation and process behaviors:

- Command lines referencing `mmap` or `mmap2`
- Use of `MAP_PRIVATE` and `MAP_ANONYMOUS` with `fd=-1`
- Memory regions staged with `PROT_NONE` and/or `PROT_EXEC`
- Large memory allocations (64MB, 128MB, 512MB)
- Process or file names such as `memfd.*` or `kworker*`

These patterns are indicative of fileless malware staging memory for payload injection and execution.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (CommandLine=/.*mmap.*/i OR CommandLine=/.*mmap2.*/i)  
| (CommandLine=/.*MAP_PRIVATE.*MAP_ANONYMOUS.*/i AND CommandLine=/.*fd=-1.*/i)  
| (CommandLine=/.*PROT_NONE.*/i)  
| (CommandLine=/.*(64M|128M|512M).*/i)  
| (CommandLine=/.*PROT_EXEC.*/i)  
| (FileName=/^memfd\..*/i OR FileName=/kworker.*/i)   
```

---

## Data Sources

| Log Provider | Event ID | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|--------------------|---------------------|------------------------|
| Falcon       | N/A      | SysmonEvent        | Process, Memory     | Syscall, Memory Alloc  |
| Falcon       | N/A      | ProcessRollup2     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker or user must be able to invoke syscalls and allocate large anonymous memory regions.
- **Required Artifacts:** Syscall logs, process creation logs, memory allocation logs.

---

## Considerations

- Review the context of large anonymous memory allocations and their subsequent use.
- Investigate the parent process and user context for privilege escalation or lateral movement.
- Correlate with threat intelligence for process and memory allocation enrichment.
- Examine for additional persistence or lateral movement mechanisms.

---

## False Positives

False positives may occur if:

- Legitimate applications allocate large anonymous memory regions for performance or sandboxing.
- System processes or security tools use similar memory allocation techniques.
- Internal testing or red team activity mimics fileless malware behavior.

---

## Recommended Response Actions

1. Investigate the process and user responsible for the suspicious memory allocation.
2. Review the memory regions and their permissions for injected or staged payloads.
3. Analyze the process for fileless malware artifacts or obfuscation techniques.
4. Check for additional persistence or lateral movement mechanisms.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1055.012 – memfd_create Injection Technique](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK: T1027.002 – Obfuscated Files or Information: Gobfuscate](https://attack.mitre.org/techniques/T1027/002/)
- [MITRE ATT&CK: T1106 – Native API Execution](https://attack.mitre.org/techniques/T1106/)
- [MITRE ATT&CK: T1497.001 – Virtualization/Sandbox Evasion: Delayed Execution](https://attack.mitre.org/techniques/T1497/001/)
- [MITRE ATT&CK: T1203 – Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [UNC5174’s evolution in China’s ongoing cyber warfare: From SNOWLIGHT to VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-24 | Initial Detection | Created hunt query to detect suspicious mmap/mmap2 usage in fileless malware (VShell)      |
