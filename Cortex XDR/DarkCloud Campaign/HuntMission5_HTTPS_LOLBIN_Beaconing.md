# Detection of Suspicious HTTPS Connections by Script/LOLBIN Processes

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Network-HTTPS-LOLBIN-Exfil
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects potential **beaconing or exfiltration** over HTTPS originating from Windows processes commonly abused for **fileless activity** and **living-off-the-land** operations. It focuses on outbound TCP/443 connections initiated by: `powershell.exe`, `pwsh.exe`, `rundll32.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `certutil.exe`, `curl.exe`, and `bitsadmin.exe`.  
To reduce noise, the hunt prioritizes **rare destinations per host** by counting connections per `(agent_id, process, remote IP)` and keeping small counts, which are often indicative of initial beaconing or short-lived exfil.

Detected behaviors include:

- HTTPS connections from high-risk scripting/LOLBIN processes
- Rare or infrequent connections per host → potential beaconing
- User-launched or unsigned processes initiating egress

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0010 - Exfiltration        | T1041       | —            | Exfiltration Over C2 Channel                   |
| TA0011 - Command & Control   | T1071.001   | —            | Application Layer Protocol: Web Protocols      |

---

## Hunt Query Logic

This query identifies suspicious network activity by:

- Scoping to **Windows** and **network events** with destination port **443**.
- Selecting events where the **initiating process** is a common LOLBIN or scripting engine.
- Aggregating connection counts per host/process/destination IP and filtering for **low-frequency** patterns (`conn_count <= 3`).

Analysts may further enrich with **signer/parent process** or **user/session** context to separate legitimate admin activity from abuse.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Suspicious HTTPS by Scripting/LOLBIN Processes
// Description: Finds outbound 443 connections from high-risk processes typically used for fileless operations, prioritizing rare destinations per host.
// MITRE ATT&CK TTP ID: T1041 (Exfiltration Over C2 Channel)
// MITRE ATT&CK TTP ID: T1071.001 (Application Layer Protocol: Web Protocols)

config case_sensitive = false

| dataset = xdr_data

| filter agent_os_type = ENUM.AGENT_OS_WINDOWS

| filter event_type = NETWORK   // valid event type for network events

| filter action_remote_port = 443 and action_local_port > 0

| fields _time, agent_hostname, agent_id, action_local_ip, action_remote_ip, action_remote_port, action_country,
         actor_process_image_name, actor_process_image_path, actor_process_command_line,
         actor_effective_username, event_id, _product

| filter actor_process_image_name in ("powershell.exe","pwsh.exe","rundll32.exe","mshta.exe","wscript.exe","cscript.exe","certutil.exe","curl.exe","bitsadmin.exe")

| comp count() as conn_count by agent_id, actor_process_image_name, action_remote_ip

| filter conn_count <= 3

| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name   | ATT&CK Data Source | ATT&CK Data Component        |
|--------------|--------------|--------------------|-------------------------------|
| Cortex XSIAM | xdr_data     | Network Traffic    | Connection                    |
| Cortex XSIAM | xdr_data     | Process            | Process Creation (enrichment) |

---

## Execution Requirements

- **Required Permissions:** Ability for user or process to initiate outbound HTTPS connections.
- **Required Artifacts:** Network telemetry linking processes to connections; process metadata including command line, signer, and parent.

---

## Considerations

- Correlate with **process signer** (unsigned or untrusted publishers) and **parent process** (e.g., Office, browser, archive extractor).  
- Review **destination reputation** and **WHOIS/ASN** for action\_remote\_ip; prioritize **new or rare** infrastructure per environment.  
- Combine with **DNS** and **HTTP(S) SNI/URL** metadata where available to improve precision.  
- Consider extending to non-443 (e.g., 8443) if your environment allows alternate HTTPS ports.

---

## False Positives

- Legitimate admin or automation use of `curl.exe`, `powershell.exe` (e.g., configuration scripts, software deployment).  
- Windows components or update mechanisms using `bitsadmin.exe` in legacy environments.  
- Security tools performing health checks or cloud API calls.

**Tuning Ideas**
- Maintain allow-lists of **known-good** destination IPs/domains and **service accounts**.  
- Raise `conn_count` threshold in environments with frequent but benign tool usage (e.g., `<= 5` or `<= 10`).  
- Require **new destination** in last 7–30 days (if telemetry supports it).

---

## Recommended Response Actions

1. Enrich with process tree, signer, and parent. Determine if the execution is **user-initiated** or scripted.  
2. Triangulate with DNS/Proxy logs for domain, SNI, and URL paths.  
3. Inspect payloads or content if SSL inspection/proxy logs are available.  
4. If malicious, **isolate the host**, block the destination, and collect memory/artifacts for exfil tool discovery.  
5. Hunt laterally for similar connections across the estate (same process, same remote IP/ASN).

---

## References

- [MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)  
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-08-18 | Initial Detection | Beaconing/exfil over HTTPS by scripting/LOLBIN processes (rare dst)|
