# Detection: CORNFLAKE.V3 C2 Initialization to 159.69.3[.]151 with Host/IP Fallback and Retry Logic

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-C2-159_69_3_151-NodeLineage
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low (due to node.exe lineage and specific IP)

---

## Hunt Analytics
This hunt focuses on detecting CORNFLAKE.V3 command-and-control initialization behavior characterized by resilient mainloop beacons:

- Repeated HTTP communication attempts to a hard-coded C2 reachable via both hostname and raw IP, specifically `159.69.3[.]151`.
- Fallback behavior from hostname to IP, with periodic retries and extended delays indicative of resilience.
- Correlation of network events to the staged Node runtime under `%APPDATA%\\node-v22.11.0-win-x64\\node.exe` to reduce false positives.
- Periodicity traits: short initial retry around ~10 seconds, converging to steady-state beacons near ~5 minutes.

Use alongside earlier hunts for initial PowerShell delivery, Node staging, and reconnaissance to stitch a full incident timeline.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                  |
|------------------------------|------------|--------------|---------------------------------|
| TA0011 - Command and Control | T1071.001  | 001          | Web Protocols                   |
| TA0002 - Execution           | T1059      |              | Command and Scripting Interpreter |

---

## Hunt Query Logic
Narrows detection to Windows network events where the destination is `159.69.3.151` and the process lineage includes the staged Node path under `%APPDATA%`. This coupling significantly reduces benign traffic while surfacing likely CORNFLAKE.V3 C2 attempts.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex XSIAM)

```xql
// Title: Node.exe in %APPDATA% reaching 159.69.3.151
// Description: Narrows detection to connections where lineage or parent includes the staged Node path (%APPDATA%\node-v22.11.0-win-x64\node.exe).
// MITRE ATT&CK TTP ID: T1071.001
// MITRE ATT&CK TTP ID: T1059

config case_sensitive = false  
| dataset = xdr_data  
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS  
  and event_type = ENUM.NETWORK  
  and dst_agent_ip_addresses = "159.69.3.151"  
  and (  
    action_process_image_name = "node.exe"  
    or actor_process_image_name = "node.exe"  
    or causality_actor_process_image_name = "node.exe"  
  )  
  and (  
    action_process_image_path contains "\AppData\Roaming\node-v22.11.0-win-x64"  
    or actor_process_image_path contains "\AppData\Roaming\node-v22.11.0-win-x64"  
    or causality_actor_process_image_path contains "\AppData\Roaming\node-v22.11.0-win-x64"  
  )  
| fields _time, agent_hostname, actor_effective_username,  
  action_process_image_name, action_process_image_path, action_process_image_command_line,  
  dst_agent_ip_addresses, http_method,  
  actor_process_image_name, actor_process_image_path, actor_process_command_line,  
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line,  
  event_id, agent_id, _product  
| sort desc _time   
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Network            | Network Traffic       |
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user sufficient; Node runs under user profile.
- **Required Artifacts:** Network telemetry with process attribution fields; process lineage data to correlate to `%APPDATA%` Node path.

---

## Considerations
- Tune for both hostname and IP if DNS logs indicate related domains; this query focuses on the raw IP to minimize ambiguity.
- Consider sequencing/periodicity analysis: cluster connections from the same host/user showing ~10s retries then ~5m steady-state to increase confidence.
- Cross-reference with prior detections (Run dialog PSH, Node staging, recon bundle) for high-fidelity incident chains.

---

## False Positives
- Low. Legitimate Node traffic from `%APPDATA%` to this exact IP is unlikely. Validate any rare developer tooling before suppression.

---

## Recommended Response Actions
1) Immediate containment:
   - Isolate affected endpoints and block `159.69.3.151` at perimeter and EDR.
2) Forensics & scoping:
   - Retrieve process lineage, memory dumps if feasible, and artifacts under `%APPDATA%\\node-v22.11.0-win-x64\\`.
3) Eradication:
   - Remove staged Node directories; revoke persistence mechanisms identified in prior hunts.
4) Monitoring:
   - Add rules for Node-in-user-profile reaching suspicious IPs/domains; set beacon-periodicity analytics.

---

## References
- MITRE ATT&CK: T1071.001 - Web Protocols https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK: T1059 - Command and Scripting Interpreter https://attack.mitre.org/techniques/T1059/

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | Node.exe lineage connections to 159.69.3.151 from %APPDATA% staging. |
