
# Detection of HazyBeacon DLL Sideloading

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-DLLSideloading-HazyBeacon
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a specific DLL sideloading technique used to deploy the HazyBeacon backdoor. The query identifies instances where the legitimate .NET Framework process, `mscorsvw.exe`, loads a malicious DLL named `mscorsvc.dll` from the non-standard `C:\Windows\assembly\` directory. This behavior is a high-fidelity indicator of the HazyBeacon implant, as the legitimate version of this DLL resides within the .NET Framework's own directory structure, not directly in the GAC's root.

Detected behaviors include:
- A `LOAD_IMAGE` event for `mscorsvc.dll`.
- The loading process is `mscorsvw.exe`.
- The path of the loaded DLL is `C:\Windows\assembly\mscorsvc.dll`.

This technique is associated with initial access, defense evasion, and persistence.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0005 - Defense Evasion      | T1574       | T1574.002    | Hijack Execution Flow: DLL Sideloading         |

---

## Hunt Query Logic

This query identifies the specific DLL sideloading event by looking for:

- `LOAD_IMAGE` events on Windows endpoints.
- The acting process name is `mscorsvw.exe`.
- The path of the loaded module is exactly `C:\Windows\assembly\mscorsvc.dll`.

A match for this logic is a strong indicator of the HazyBeacon backdoor.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: HazyBeacon DLL Sideloading via mscorsvw.exe
// Description: Detects the mscorsvw.exe process loading a DLL named mscorsvc.dll from the C:\Windows\assembly\ directory, a known TTP for the HazyBeacon backdoor.
// MITRE ATT&CK TTP ID: T1574.002

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.LOAD_IMAGE 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and actor_process_image_name = "mscorsvw.exe"
    and action_module_path = "C:\Windows\assembly\mscorsvc.dll"
| fields _time, agent_hostname, actor_process_image_path, actor_process_command_line, action_module_path, action_module_sha256, causality_actor_process_image_name, causality_actor_process_command_line, event_id, agent_id, _product
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Module              | Module Load            |

---

## Execution Requirements

- **Required Permissions:** The attacker must have sufficient permissions to write a file to the `C:\Windows\assembly\` directory.
- **Required Artifacts:** Endpoint logs capturing module load events (`LOAD_IMAGE`).

---

## Considerations

- Upon alert, immediately investigate the SHA256 hash of the `action_module_path` (`mscorsvc.dll`) and compare it against known malicious hashes.
- Examine the parent process of `mscorsvw.exe` to understand how it was initiated.
- Correlate this activity with subsequent network connections from `mscorsvw.exe`, especially to domains ending in `.on.aws`, to identify C2 traffic.
- Hunt for the associated persistence mechanism, which is the creation of a Windows service named `msdnetsvc`.

---

## False Positives

- False positives are highly unlikely. The legitimate `mscorsvc.dll` is part of the .NET Framework and does not reside in this specific path. Any hit should be treated as a true positive until proven otherwise.

---

## Recommended Response Actions

1.  Isolate the affected endpoint from the network to contain the threat.
2.  Acquire the malicious DLL from `C:\Windows\assembly\mscorsvc.dll` for forensic analysis.
3.  Investigate the host for further signs of compromise, including the other payloads and TTPs associated with HazyBeacon (e.g., files in `C:\ProgramData`, service creation).
4.  Remediate the host by removing the malicious DLL and any associated persistence mechanisms.
5.  Block any identified C2 domains or IPs at the network perimeter.

---

## References

- [Unit 42: HazyBeacon: An In-Depth Look at a New Windows Backdoor for Novel C2 Communication](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)
- [MITRE ATT&CK: T1574.002 – Hijack Execution Flow: DLL Sideloading](https://attack.mitre.org/techniques/T1574/002/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect the specific DLL sideloading technique used by the HazyBeacon backdoor. |
