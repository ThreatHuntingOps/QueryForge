# Detection of LDAPSearch for Active Directory Kerberoastable Accounts

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-LDAPSearch-Kerberoasting
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of `ldapsearch.exe` to query Active Directory for user accounts that have a Service Principal Name (SPN) configured. This is a classic reconnaissance step for a Kerberoasting attack. The threat actor's goal is to identify service accounts, request their Kerberos tickets, and then crack them offline to steal the account's plaintext password. The query also looks for command-line output redirection (`>`), which indicates the actor is saving the list of accounts to a file. The presence and execution of `ldapsearch.exe` on a standard Windows endpoint is highly anomalous and a strong indicator of malicious activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0007 - Discovery            | T1087       | .002         | Account Discovery: Domain Account              |
| TA0006 - Credential Access    | T1558       | .003         | Steal or Forge Kerberos Tickets: Kerberoasting |

---

## Hunt Query Logic

This query identifies the reconnaissance phase of a Kerberoasting attack by looking for:

- The execution of `ldapsearch.exe`, a non-native Windows tool.
- The presence of `serviceprincipalname` in the command line, indicating a search for SPNs.
- The use of the output redirection character (`>`), suggesting the results are being saved to a file.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: LDAPSearch for Kerberoastable Accounts
// Description: Detects the use of ldapsearch.exe to find accounts with a Service Principal Name (SPN) and dump the output to a file, a common precursor to a Kerberoasting attack.
// MITRE ATT&CK TTP ID: T1558.003
// MITRE ATT&CK TTP ID: T1087.002

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and action_process_image_name = "ldapsearch.exe" 
    and action_process_image_command_line contains "serviceprincipalname" 
    and action_process_image_command_line contains ">" 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Any authenticated domain user can query Active Directory for SPNs. The attacker needs to have placed the `ldapsearch.exe` binary on the host.
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- **High Fidelity:** `ldapsearch.exe` is not a native Windows tool. Its presence on a workstation or member server is highly suspicious.
- **Key Artifacts:** The output file specified in the command line is a critical artifact containing the list of targeted accounts. The `ldapsearch.exe` binary itself should also be collected for analysis.
- **Follow-on Activity:** This activity is almost always a precursor to Kerberos ticket requests (TGS-REQ) for the identified SPNs.

---

## False Positives

- False positives are extremely rare. A legitimate administrator might use this tool for diagnostic purposes, but this would be unusual and should be easily verifiable. Any alert should be treated as a likely true positive.

---

## Recommended Response Actions

1.  **Isolate Host:** Immediately isolate the host (`agent_hostname`) where `ldapsearch.exe` was executed to prevent the next stage of the attack.
2.  **Collect Artifacts:** Secure the output file (e.g., `users.txt`) and the `ldapsearch.exe` binary for forensic analysis.
3.  **Investigate Source:** Determine how `ldapsearch.exe` was introduced to the system. Analyze the parent process (`actor_process_image_name`) and associated user activity.
4.  **Review Target Accounts:** Analyze the list of accounts in the output file. These are the accounts the attacker is targeting. Proactively review them for signs of compromise and consider resetting their passwords, especially if they are known to be weak.
5.  **Hunt for TGS-REQs:** Hunt for Kerberos event logs (Event ID 4769) on your Domain Controllers, looking for a high volume of requests originating from the source host for the SPNs identified in the output file.

---

## References

- [MITRE ATT&CK: T1558.003 – Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK: T1087.002 – Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created hunt query to detect Kerberoasting reconnaissance via ldapsearch. |
