# Detection of Sliver Implant and In-Memory VShell Backdoor Deployment

## Hunt Analytics Metadata

- **ID:** `HuntQuery-CrowdStrike-UNC5174Persistence`
- **Operating Systems:** `LinuxEndpoint`, `Unix`
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt query is designed to detect persistence techniques associated with UNC5174, particularly focusing on the deployment of the Sliver C2 implant and an in-memory VShell backdoor. It identifies behaviors typically observed post-initial access, such as the execution of bash scripts that retrieve and stage malicious payloads using tools like `curl` or `wget`, and follow-on commands that introduce obfuscated binaries such as `system_worker`, `dnsloger`, and `vshell`.

Observed behaviors include:

- Execution of shell scripts to stage backdoors
- Use of `curl` or `wget` for payload retrieval
- Execution of suspicious binaries consistent with UNC5174’s toolkit
- Indicators of in-memory execution and process hollowing

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                     |
|------------------------------|------------|---------------|--------------------------------------------------|
| TA0002 - Execution            | T1059.004 | —             | Command and Scripting Interpreter: Unix Shell     |
| TA0011 - Command and Control  | T1105     | —             | Ingress Tool Transfer                              |
| TA0005 - Defense Evasion      | T1055.012 | —             | Process Injection: Process Hollowing              |
| TA0003 - Persistence          | T1546.001 | —             | Event Triggered Execution: At (Linux)             |
| TA0005 - Defense Evasion      | T1574.002 | —             | Hijack Execution Flow: DLL Side-Loading           |

---

## Hunt Query Logic

The query captures process execution events where:

- The command line includes keywords such as `bash`, `curl`, `wget`, or execution permission changes (`chmod +x`)
- Suspicious binaries such as `system_worker`, `sliver`, `vshell`, or `dnsloger` are invoked
- The parent process indicates scripting language usage (e.g., `bash`, `sh`, or `python`)

These indicators point to staged in-memory implants or execution of lateral movement components post-initial compromise.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 OR #event_simpleName=ProcessCreation 
| (CommandLine = "*bash*" OR CommandLine = "*curl*" OR CommandLine = "*wget*" OR CommandLine = "*chmod +x*") 
| (CommandLine = "*system_worker*" OR CommandLine = "*dnsloger*" OR CommandLine = "*sliver*" OR CommandLine = "*vshell*") 
| (ParentBaseFileName = "bash" OR ParentBaseFileName = "sh" OR ParentBaseFileName = "python")
```

---

## Data Sources

| Log Provider | Event Name        | ATT&CK Data Source | ATT&CK Data Component |
|--------------|-------------------|--------------------|------------------------|
| Falcon       | ProcessRollup2    | Process             | Process Creation       |
| Falcon       | ProcessCreation   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute shell scripts or binaries.
- **Required Artifacts:** Bash scripts, downloaded payloads, memory-resident executables.

---

## Considerations

- Investigate the source of downloaded files and IP/domain associated with `curl`/`wget`
- Identify whether suspicious binaries (`system_worker`, `dnsloger`, etc.) are known or signed
- Validate timing and process relationships for signs of in-memory backdoor activity
- Correlate file hashes and paths against threat intelligence feeds

---

## False Positives

False positives may occur in the following scenarios:

- System administrators running benign shell scripts that retrieve external resources
- Security testing frameworks or EDR tools mimicking attack behavior for simulation
- Developers using custom-named binaries during legitimate script executions

---

## Recommended Response Actions

1. Isolate the system if suspicious binaries or memory-resident tools are confirmed.
2. Analyze the full process chain for signs of lateral movement or privilege escalation.
3. Extract and reverse-engineer any unknown binaries (e.g., `system_worker`, `dnsloger`).
4. Inspect persistence mechanisms such as cron jobs or systemd service modifications.
5. Review network logs for connections to known UNC5174 infrastructure.

---

## References

- [MITRE ATT&CK: T1059.004 – Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1055.012 – Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK: T1546.001 – At (Linux)](https://attack.mitre.org/techniques/T1546/001/)
- [MITRE ATT&CK: T1574.002 – DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [UNC5174’s evolution in China’s ongoing cyber warfare: From SNOWLIGHT to VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)

---

## Version History

| Version | Date       | Impact             | Notes                                                              |
|---------|------------|--------------------|--------------------------------------------------------------------|
| 1.0     | 2025-04-21 | Initial Detection | Created query to detect UNC5174 persistence and in-memory backdoors |
