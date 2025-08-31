
# Detection of HazyBeacon Persistence via Service Creation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-ServiceCreation-HazyBeacon
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt targets the specific persistence mechanism established by the HazyBeacon backdoor. The query detects the command-line execution of `sc.exe` (Service Control Manager) being used to create a new Windows service named `msdnetsvc`. The threat actor creates this service to point to the `mscorsvw.exe` executable, ensuring the malicious sideloaded DLL is re-loaded every time the system reboots.

Detected behaviors include:
- Process launch of `sc.exe`.
- Command line containing the `create` argument.
- Command line containing the specific service name `msdnetsvc`.

This technique is a classic and high-fidelity indicator of persistence.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0003 - Persistence          | T1543       | T1543.003    | Create or Modify System Process: Windows Service |

---

## Hunt Query Logic

This query identifies the specific service creation event by looking for:

- `PROCESS_START` events on Windows endpoints.
- The process name is `sc.exe`.
- The command line contains both the string `create` and the specific service name `msdnetsvc`.

A match for this logic is a strong indicator of the HazyBeacon backdoor establishing persistence.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: HazyBeacon Persistence Service Creation "msdnetsvc"
// Description: Detects the creation of the Windows service "msdnetsvc" which is used by the HazyBeacon backdoor for persistence.
// MITRE ATT&CK TTP ID: T1543.003

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name = "sc.exe"
    and (action_process_image_command_line contains "create" and action_process_image_command_line contains "msdnetsvc")
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, event_id, agent_id, _product
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The attacker must have administrative privileges to create a new system service.
- **Required Artifacts:** Endpoint logs capturing process creation events with full command-line arguments.

---

## Considerations

- Upon alert, immediately investigate the configuration of the newly created service by running `sc qc msdnetsvc` on the affected host to confirm the `BINARY_PATH_NAME`.
- Correlate this activity with the DLL sideloading event (Hunt Query 1) on the same host.
- Investigate the parent process that executed the `sc.exe` command to trace the attack chain.

---

## False Positives

- False positives are extremely unlikely. The service name `msdnetsvc` is specific to this threat actor's TTPs. Any hit should be treated as a true positive until proven otherwise.

---

## Recommended Response Actions

1.  Isolate the affected endpoint from the network.
2.  Disable and delete the malicious service using `sc stop msdnetsvc` and `sc delete msdnetsvc`.
3.  Investigate the host for the initial sideloading event and any subsequent payloads dropped by the backdoor.
4.  Remediate the host by removing the malicious DLL and any other artifacts.
5.  Review other systems in the environment for the presence of this service.

---

## References

- [Unit 42: HazyBeacon: An In-Depth Look at a New Windows Backdoor for Novel C2 Communication](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)
- [MITRE ATT&CK: T1543.003 – Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect the specific persistence mechanism (service creation) used by the HazyBeacon backdoor. |
