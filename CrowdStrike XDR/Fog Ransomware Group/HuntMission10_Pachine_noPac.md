# Detection of Privilege Escalation in Active Directory via Pachine and noPac (CVE-2021-42278 & CVE-2021-42287)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Pachine-noPac-ADEscalation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt query detects indicators associated with the exploitation of CVE-2021-42278 and CVE-2021-42287, commonly abused via the Pachine and noPac tools. These vulnerabilities allow attackers to impersonate domain controllers or escalate privileges to Domain Admin by manipulating Kerberos tickets and machine account attributes.

Key behaviors include:

- Use of ticket manipulation tools like Rubeus, kekeo, sekurlsa
- Command-line indicators such as `--impersonate`, `--target`, `--tgtdeleg`, `--ptt`
- Detection of payloads or binaries referencing `npac`, `pachine`
- Creation or manipulation of computer accounts using specific flags
- Use of Python, PowerShell, or CMD to execute suspicious actions

These techniques enable full domain compromise when successfully exploited.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                               |
|------------------------------|--------------|---------------|--------------------------------------------------------------|
| TA0004 - Privilege Escalation | T1068       | —             | Exploitation for Privilege Escalation                        |
| TA0006 - Credential Access    | T1003.001   | —             | OS Credential Dumping: LSASS Memory                          |
| TA0006 - Credential Access    | T1558.001   | —             | Steal or Forge Kerberos Tickets: Golden Ticket              |
| TA0006 - Credential Access    | T1550.003   | —             | Use Alternate Authentication Material: Pass the Ticket       |
| TA0006 - Credential Access    | T1078       | —             | Valid Accounts                                               |

---

## Hunt Query Logic

The query identifies command-line indicators of Kerberos ticket forging, impersonation, and shell launching typically used by tools like Pachine and noPac. It looks for:

- Ticket crafting parameters (`--impersonate`, `--target`, `--tgtdeleg`, `--ptt`, etc.)
- Domain controller impersonation (`-dc-ip`, `-shell`)
- Known offensive tool indicators (`Rubeus`, `kekeo`, `sekurlsa`)
- Suspicious filenames or arguments referencing `npac` or `pachine`
- Execution via scripting engines or shells (`python.exe`, `pwsh.exe`, `cmd.exe`)

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2   
| (CommandLine = "*-rc4*" OR CommandLine = "*--impersonate*" OR CommandLine = "*--target*"  
OR CommandLine = "*--downgrade*" OR CommandLine = "*--ticket*"  
OR CommandLine = "*-dc-ip*" AND CommandLine = "*-shell*"  
OR CommandLine = "*--tgtdeleg*" OR CommandLine = "*--ptt*"  
OR FileName = /npac/i OR FileName = /pachine/i  
OR CommandLine = "*kekeo*" OR CommandLine = "*Rubeus*" OR CommandLine = "*sekurlsa*")  
| (ImageFileName = "*python.exe*" OR ImageFileName = "*pwsh.exe*" OR ImageFileName = "*cmd.exe*")
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Access to execute ticket forging tools and create/modify machine accounts.
- **Required Artifacts:** Command-line arguments and tool signatures associated with Pachine/noPac exploitation.

---

## Considerations

- Correlate findings with Domain Controller logs and Kerberos authentication failures.
- Investigate any new machine accounts or password changes via command line.
- Examine TGT or TGS ticket requests from unexpected accounts or machines.

---

## False Positives

False positives may occur if:

- Red teams or internal security staff use Rubeus or similar tools for authorized testing.
- Labs or sandbox environments simulate Kerberos ticket operations.

---

## Recommended Response Actions

1. Isolate systems involved in suspicious Kerberos manipulation.
2. Invalidate forged tickets and reset compromised machine accounts.
3. Audit recent SPN changes and Kerberos logs in the domain.
4. Perform memory capture on suspected systems for LSASS dumping validation.
5. Review for lateral movement or exfiltration following ticket creation.

---

## References

- [CVE-2021-42278 – SAM Account Name Spoofing](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [CVE-2021-42287 – Kerberos Privilege Escalation](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)
- [Rubeus – Toolset for Kerberos Abuse](https://github.com/GhostPack/Rubeus)
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact              | Notes                                                                                 |
|---------|------------|---------------------|---------------------------------------------------------------------------------------|
| 1.0     | 2025-05-02 | Initial Detection   | Detection query for Pachine and noPac exploitation of CVE-2021-42278 & 42287         |
