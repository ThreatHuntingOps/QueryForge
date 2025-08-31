
# Threat Hunt Hypothesis: HazyBeacon Backdoor Activity

### Based on Threat Intelligence From: 
[Unit42: Novel Covert C2 Communication](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)

---

## Hypothesis Statement
A threat actor, consistent with the activity cluster CL-STA-1020, has compromised Windows endpoints by sideloading a malicious DLL (`mscorsvc.dll`) via a legitimate .NET Framework process (`mscorsvw.exe`). This implant establishes persistence through a custom Windows service (`msdnetsvc`), communicates with C2 infrastructure using AWS Lambda URLs, and stages data for exfiltration in `C:\ProgramData` using custom tools and legitimate utilities like 7-Zip before attempting to upload it to cloud storage services like Google Drive or Dropbox.

## Purpose
This hypothesis guides a targeted hunt to detect the end-to-end attack chain of the HazyBeacon backdoor. The goal is to identify compromised hosts by searching for specific and high-fidelity indicators of compromise (IOCs) and behavioral artifacts (TTPs) associated with this threat actor's operations, from initial execution to final exfiltration and cleanup.

## Supporting Threat Intelligence
This hypothesis is based on the TTPs reported by Unit 42 in the analysis of the HazyBeacon backdoor:
- **Initial Execution & Defense Evasion:** DLL sideloading where `mscorsvw.exe` loads a malicious `mscorsvc.dll` from the non-standard `C:\Windows\assembly\` directory.
- **Persistence:** Creation of a Windows service named `msdnetsvc` that points to `mscorsvw.exe` to ensure the backdoor survives reboots.
- **Command & Control:** Network connections from compromised processes to AWS Lambda URLs, identified by domains ending in `.on.aws`.
- **Collection & Staging:** Use of a custom file collector (`igfx.exe`) and a legitimate archiving utility (`7z.exe`) dropped in `C:\ProgramData`. Data is staged by creating archives and splitting them into smaller volumes.
- **Exfiltration:** Use of custom uploader tools (`GoogleGet.exe`, `GoogleDrive.exe`, `Dropbox.exe`, etc.) executed from `C:\ProgramData`.
- **Indicator Removal:** Deletion of the dropped payloads and created archives from `C:\ProgramData` to cover tracks.

## Testability
This hypothesis is testable by executing a series of structured queries against endpoint detection and response (EDR) and network data logs. The hunt should look for:
1.  `mscorsvw.exe` loading `mscorsvc.dll` from `C:\Windows\assembly\`.
2.  Creation of a Windows service named `msdnetsvc`.
3.  Outbound network connections from `mscorsvw.exe` to domains containing `.on.aws`.
4.  Execution of known HazyBeacon payload names from the `C:\ProgramData` directory.
5.  Execution of `7z.exe` from `C:\ProgramData`, especially with command-line flags for creating volumes (`-v`).
6.  Execution of `cmd.exe` or `powershell.exe` to delete the known payload files from `C:\ProgramData`.
