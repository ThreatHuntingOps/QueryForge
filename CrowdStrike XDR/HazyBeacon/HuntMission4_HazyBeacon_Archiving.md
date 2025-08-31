
# Detection of Anomalous Data Archiving for Exfiltration

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-DataArchiving-HazyBeacon
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a specific data staging behavior used by the HazyBeacon threat actor. The query identifies the execution of the 7-Zip utility, `7z.exe`, from the non-standard `C:\ProgramData` directory. Furthermore, it looks for command-line arguments that indicate the creation of an archive file (e.g., `.zip`, `.7z`). This combination of an out-of-place legitimate tool being used for data aggregation is a strong behavioral indicator that an attacker is collecting and compressing data before exfiltration.

Detected behaviors include:
- Process execution of `7z.exe` from `C:\ProgramData`.
- Command line containing common archive file extensions.

This technique is a key step in the Collection and Staging phases of an attack.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0009 - Collection           | T1560       | T1560.001    | Archive Collected Data: Archive via Utility    |
| TA0009 - Collection           | T1074       | T1074.001    | Data Staged: Local Data Staging                |

---

## Hunt Query Logic

This query identifies anomalous data archiving by looking for:

- `PROCESS_START` events on Windows endpoints.
- The process image path is exactly `C:\ProgramData\7z.exe`.
- The command line contains strings associated with archive creation, such as `.zip`, `.7z`, `.rar`, or `.tar`.

A match for this logic is a strong indicator of malicious data staging activity.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Suspicious Data Archiving with 7z.exe from C:\ProgramData
// Description: Detects the 7-Zip utility being executed from the C:\ProgramData directory to create an archive, a known TTP for data staging by the HazyBeacon threat actor.
// MITRE ATT&CK TTP ID: T1560.001
// MITRE ATT&CK TTP ID: T1074.001

#event_simpleName=ProcessRollup2 
| event_platform = Win
| FilePath =* "\\ProgramData\\7z.exe"
| (CommandLine =* ".zip" OR CommandLine =* ".7z" OR CommandLine =* ".rar" OR CommandLine =* ".tar")
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId]) 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The attacker must have permissions to write and execute files in the `C:\ProgramData` directory.
- **Required Artifacts:** Endpoint logs capturing process creation events with full command-line arguments.

---

## Considerations

- Upon alert, examine the full command line to identify the source files being archived and the name/location of the output archive.
- Investigate the parent process of `7z.exe`. In the HazyBeacon attack chain, this could be `igfx.exe` or another script/payload.
- Look for subsequent activity involving the created archive file, such as splitting it into smaller volumes or uploading it to a cloud service.

---

## False Positives

- False positives are very low. Legitimate software rarely, if ever, installs or runs `7z.exe` from the root of `C:\ProgramData`. Any such activity should be considered suspicious and investigated.

---

## Recommended Response Actions

1.  Isolate the affected endpoint.
2.  Acquire the created archive file(s) for forensic analysis to understand what data was stolen.
3.  Acquire the `7z.exe` binary from `C:\ProgramData` to verify its hash.
4.  Investigate the host for the full HazyBeacon attack chain.
5.  Remediate the host by removing all malicious files and persistence.

---

## References

- [Unit 42: HazyBeacon: An In-Depth Look at a New Windows Backdoor for Novel C2 Communication](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)
- [MITRE ATT&CK: T1560.001 – Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)
- [MITRE ATT&CK: T1074.001 – Data Staged: Local Data Staging](https://attack.mitre.org/techniques/T1074/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect the behavioral TTP of data staging via an out-of-place 7-Zip executable. |
