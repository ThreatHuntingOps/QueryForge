# Detection of Anubis Ransomware Wiper Activity via /WIPEMODE Parameter

## Severity or Impact of the Detected Behavior
- **Risk Score:** 99
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnubisWipeMode
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Extremely Low

---

## Hunt Analytics

This hunt detects process executions that leverage the `/WIPEMODE` parameter, which is used by Anubis ransomware to irreversibly erase file contents, leaving files present but with zero size. This destructive behavior is a strong indicator of wiper activity and can result in permanent data loss, making early detection critical. The `/WIPEMODE` parameter is rarely seen in legitimate software and is highly suspicious in most environments.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1485       | —            | Data Destruction                              |
| TA0040 - Impact              | T1490       | —            | Inhibit System Recovery                       |
| TA0040 - Impact              | T1486       | —            | Data Encrypted for Impact                     |

---

## Hunt Query Logic

This query identifies process execution events where the command line includes the `/WIPEMODE` parameter in any form. This behavior is associated with wiper functionality that erases file contents, as observed in Anubis ransomware attacks. The query can be further refined by correlating with parent process, user context, or frequency of these events.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (CommandLine = "*/WIPEMODE*" OR CommandLine = "*/WIPEMODE=*" OR CommandLine = "*/WIPEMODE *")
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute processes with custom command-line arguments.
- **Required Artifacts:** Process creation logs with full command-line capture.

---

## Considerations

- Correlate with other signs of ransomware or wiper activity, such as file deletion, shadow copy deletion, or privilege escalation.
- Review the process tree and parent process for initial access vectors.
- Investigate the timing and frequency of `/WIPEMODE` usage.

---

## False Positives

False positives are extremely rare, but may occur if:
- Custom administrative or security tools are misconfigured to use the `/WIPEMODE` parameter (very uncommon).

---

## Recommended Response Actions

1. Isolate the affected endpoint immediately to prevent further impact.
2. Investigate the process tree and user context for signs of compromise.
3. Review for additional ransomware or wiper behaviors, such as file encryption or shadow copy deletion.
4. Collect forensic artifacts (memory, disk, logs) for further analysis.
5. Initiate incident response and recovery procedures as soon as possible.

---

## References

- [MITRE ATT&CK: T1485 – Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [Anubis: A Closer Look at an Emerging Ransomware with Built-in Wiper](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-24 | Initial Detection | Created hunt query to detect Anubis ransomware wiper activity via /WIPEMODE parameter |
