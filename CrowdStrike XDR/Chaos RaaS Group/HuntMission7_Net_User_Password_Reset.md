# Detection of Domain User Password Reset via Command Line

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-NetUser-PassReset
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the use of the `net.exe` utility to reset the password of a domain user account. Threat actors, including the Chaos group, use this command to take control of existing accounts, securing their access and potentially escalating privileges within the domain. While administrators may use this command for legitimate purposes, its execution outside of normal administrative activity, from an unexpected host, or by an unusual user account is highly suspicious and warrants immediate investigation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0003 - Persistence          | T1078       | .002         | Valid Accounts: Domain Accounts                |
| TA0004 - Privilege Escalation | T1078       | .002         | Valid Accounts: Domain Accounts                |

---

## Hunt Query Logic

This query identifies potential malicious password resets by looking for:

- The execution of the `net.exe` process.
- The presence of the `user` and `/dom` arguments in the command line, which specifically targets domain user accounts for modification.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Domain User Password Reset with net.exe
// Description: Detects the use of "net.exe" to change a domain user's password, a technique used by attackers to take over accounts for persistence.
// MITRE ATT&CK TTP ID: T1078.002

#event_simpleName=ProcessRollup2
| event_platform = Win
| (FileName = /net\.exe/i OR OriginalFileName = /net\.exe/i)
| CommandLine = "*user*"
| CommandLine = "*/dom*"
| table([EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId, PlatformName])
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The attacker must be operating from an account with sufficient privileges to reset domain user passwords (e.g., Domain Admin, Account Operator, or an account with delegated permissions).
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- **Context is Critical:** The legitimacy of this action depends entirely on the context. Who ran the command (`actor_effective_username`)? From which host (`agent_hostname`)? Was it spawned from an interactive admin session or from an automated script?
- **Baseline Activity:** It is crucial to have a baseline of normal administrative behavior. Password resets should typically originate from specific admin workstations or servers.

---

## False Positives

False positives will occur when:
- System administrators or help desk staff legitimately reset a user's password as part of their duties.
- Automated scripts that manage user accounts perform password resets.

---

## Recommended Response Actions

1.  **Verify Legitimacy:** Confirm with the user or IT team responsible for the source account (`actor_effective_username`) whether the password reset was an intentional and authorized action.
2.  **Investigate Accounts:** If the action was unauthorized, treat both the source account that ran the command and the target account whose password was changed as compromised.
3.  **Reset Passwords:** Immediately reset the passwords for both accounts involved through a secure, out-of-band process.
4.  **Isolate and Analyze:** Isolate the source host (`agent_hostname`) and analyze it for other signs of malicious activity.
5.  **Review Privileges:** Review the permissions of the compromised accounts and determine if they were excessive.

---

## References

- [MITRE ATT&CK: T1078.002 – Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [Microsoft Docs: Net user command](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11))
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-31 | Initial Detection | Created hunt query to detect domain user password resets via net.exe. |
