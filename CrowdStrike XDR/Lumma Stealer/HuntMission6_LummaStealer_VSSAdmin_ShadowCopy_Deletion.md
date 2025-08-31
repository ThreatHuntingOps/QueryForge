# Shadow Copy Deletion via vssadmin (Ransomware Preparation)

## Metadata
**ID:** HuntQuery-CrowdStrike-LummaStealer-VSSAdmin-ShadowCopy-Deletion  
**OS:** WindowsEndpoint, WindowsServer  
**FP Rate:** Low  

---

## ATT&CK Tags

| Tactic                   | Technique | Subtechnique | Technique Name                             |
|-------------------------|-----------|---------------|--------------------------------------------|
| TA0040 - Impact         | T1490     | -             | Inhibit System Recovery                     |
| TA0005 - Defense Evasion| T1070     | 006           | Indicator Removal: Timestomp or Shadow Copy |

---

## Utilized Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source | ATT&CK Data Component |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Execution      |

---

## Technical description of the attack
Ransomware groups (e.g., Black Basta) often delete shadow copies before encrypting files to prevent recovery. This behavior is frequently executed using `vssadmin.exe` with flags like `delete shadows` or `create shadow` to either remove or manipulate volume shadow copies. If Lumma is used as a dropper or loader, this activity may appear as part of the post-compromise stage.

---

## Permission required to execute the technique
Administrator

---

## Detection description
This query flags suspicious uses of `vssadmin.exe` to either delete or manipulate shadow copies, often from within user-accessible directories or system paths. While these may occur during legitimate backup/restore operations, the context of execution and timing are key for triage.

---

## Considerations
Use additional fields such as `CommandLine`, `ParentProcessId`, and `UserSid` to add context. Review adjacent process activity (e.g., backup software or script runners) to identify false positives. Pair this rule with detections for `rundll32`, `wscript`, or `powershell` to enhance fidelity.

---

## False Positives
Backup management tools or legitimate administrative scripts may invoke `vssadmin` with these parameters. Whitelist known and expected usage patterns (e.g., enterprise backup software agents).

---

## Suggested Response Actions
- Confirm process lineage and user context.
- Review system for signs of encryption, unauthorized changes, or dropped payloads.
- Search for indicators of ransomware staging or communication with known C2 endpoints.
- Isolate host and collect forensic images immediately.
- Validate whether Lumma or another loader was present prior to the execution.

---

## References
* [MITRE ATT&CK - T1490](https://attack.mitre.org/techniques/T1490/)
* [MITRE ATT&CK - T1070.006](https://attack.mitre.org/techniques/T1070/006/)
* [Threat actors using fake Chrome updates to deliver Lumma Stealer](https://security.microsoft.com/threatanalytics3/4aa69db9-9f04-46ca-b07f-c67f7105f61d/analystreport?tid=2ff60116-7431-425d-b5af-077d7791bda4&si_retry=1)

---

## Detection

**Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2
| FileName=/vssadmin/i
| (FilePath="C:\\*" OR FilePath="CSIDL_PROFILE\\documents")
| CommandLine="*create shadow*" OR CommandLine="*delete shadows*"
```

---
## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2025-04-13| Initial Detection | Created hunt query to detect shadow copy deletion via vssadmin — commonly observed in ransomware pre-encryption stages like those involving Black Basta.|
