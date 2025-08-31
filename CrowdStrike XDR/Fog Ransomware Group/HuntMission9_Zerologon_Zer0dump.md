# Detection of Zerologon Exploitation via Zer0dump Tool Usage

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Zer0dump-Zerologon
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt query identifies signs of Zerologon exploitation via the Zer0dump tool, which targets Domain Controllers to reset the machine account password to blank and potentially elevate privileges to Domain Admin. It further detects the usage of `secretsdump.py` to extract credentials post-exploitation.

Key behaviors include:

- Execution of `secretsdump.py` targeting DCs
- Resetting of machine account passwords
- DCE/RPC and NETLOGON exploitation artifacts
- Usage of tools like `python.exe`, `pwsh.exe`, or `cmd.exe`

These actions indicate a potential compromise of Active Directory, credential theft, and lateral movement preparation.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                               |
|------------------------------|--------------|---------------|--------------------------------------------------------------|
| TA0004 - Privilege Escalation | T1068       | —             | Exploitation for Privilege Escalation                        |
| TA0006 - Credential Access    | T1003.006   | —             | OS Credential Dumping: DCSync                                |
| TA0008 - Lateral Movement     | T1075       | —             | Pass the Hash                                                |
| TA0006 - Credential Access    | T1558.003   | —             | Steal or Forge Kerberos Tickets: Kerberoasting              |
| TA0002 - Execution            | T1203       | —             | Exploitation for Client Execution                           |

---

## Hunt Query Logic

The query identifies suspicious activity aligned with Zerologon exploitation:

- Use of `secretsdump.py` to dump credentials
- Command lines containing `ncacn_np`, `NETLOGON`, `zerologon`, `samr.connect`, `dcerpc`, or `resetpassword`
- Activity targeting `Administrator` or `$MACHINE.ACC` accounts
- Associated with interpreters such as Python, PowerShell, or CMD

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2   
| (FileName = /secretsdump.py/i OR CommandLine = "*secretsdump.py*")   
| (CommandLine = "*ncacn_np:*" AND CommandLine = "*\\NETLOGON*")  
| (CommandLine = "*samr.connect*" OR CommandLine = "*dcerpc*" OR CommandLine = "*zerologon*" 
OR CommandLine = "*-just-dc*" AND CommandLine = "*Administrator*") 
OR (CommandLine = "*resetpassword*" AND (CommandLine = "*$ADMIN*" OR CommandLine = "*$MACHINE.ACC*"))   
| (ImageFileName = "*python.exe*" OR ImageFileName = "*pwsh.exe*" OR ImageFileName = "*cmd.exe*")
```
**Query Language:** Cortex Query Language (XQL)  
**Platform:** Cortex XSIAM

```xql
dataset = xdr_data 
| filter event_type = PROCESS 
| filter ( lowercase(actor_process_image_name) contains "secretsdump.py" or lowercase(actor_process_command_line) contains "secretsdump.py" ) 
| filter 
(
    (lowercase(actor_process_command_line) contains "ncacn_np:" and lowercase(actor_process_command_line) contains "\\netlogon") 
    or lowercase(actor_process_command_line) in ("samr.connect", "dcerpc", "zerologon") 
    or ( lowercase(actor_process_command_line) contains "-just-dc" and lowercase(actor_process_command_line) contains "administrator") 
) 
    or (lowercase(actor_process_command_line) contains "resetpassword" and (lowercase(actor_process_command_line) contains "admin" 
    or lowercase(actor_process_command_line) contains "machine.acc")
)
| filter ( lowercase(actor_process_image_name) in ("python.exe", "pwsh.exe", "cmd.exe") )
| fields agent_hostname, actor_process_image_name, actor_process_command_line, _time
```
---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Access to run exploitation or credential dumping tools on the Domain Controller.
- **Required Artifacts:** Use of specific command-line indicators or interpreter binaries (e.g., Python).

---

## Considerations

- Confirm machine account resets or unusual credential changes.
- Correlate `secretsdump.py` activity with other lateral movement or exfiltration.
- Validate if targeted systems are critical AD infrastructure.

---

## False Positives

False positives may occur if:

- Penetration testers or red teamers are simulating Zerologon scenarios.
- Internal security tools mimic this behavior for testing.

---

## Recommended Response Actions

1. Isolate affected Domain Controller or endpoints immediately.
2. Investigate password resets for DC machine accounts.
3. Review AD logs for unauthorized privilege escalation.
4. Revert changes to machine accounts and reset credentials.
5. Initiate forensic analysis to determine breach scope.

---

## References

- [CVE-2020-1472 – Zerologon](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)
- [MITRE ATT&CK: T1003.006 – OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact              | Notes                                                                               |
|---------|------------|---------------------|-------------------------------------------------------------------------------------|
| 1.0     | 2025-05-02 | Initial Detection   | Initial release to detect Zerologon exploitation via Zer0dump tool usage            |
