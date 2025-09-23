# Detection of ESXi Virtual Machine Disruption and File Encryption by Play Ransomware

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Cortex-PlayRansomware-ESXi
- **Operating Systems:** ESXi, Linux, Virtualized Workloads
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects behaviors associated with the Play ransomware ESXi variant, including mass VM shutdown, ransom note deployment, and targeted encryption of VM-related files. It highlights suspicious use of ESXi management utilities, manipulation of welcome messages, creation of `PLAY_Readme.txt` in ESXi-specific paths, and access to virtual disk-related extensions such as `.vmdk`, `.vmem`, and `.vmx`. These behaviors are indicative of ransomware campaigns targeting virtualized environments.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                            |
|-------------------------------|-------------|--------------|----------------------------------------------------------|
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact (VM-related file encryption)    |
| TA0040 - Impact               | T1496       | —            | Resource Hijacking (Powering off all VMs)                |
| TA0005 - Defense Evasion      | T1027       | —            | Obfuscated Files or Information (unique binary)           |
| TA0040 - Impact               | T1561.002   | —            | Disk Wipe: Logical Disk Structure Wipe                   |
| TA0040 - Impact               | T1490       | —            | Inhibit System Recovery                                  |
| TA0002 - Execution            | T1202       | —            | Indirect Command Execution (via ESXi CLI utilities)      |

---

## Hunt Query Logic

This query identifies suspicious process activity related to Play ransomware targeting ESXi environments:

- Use of ESXi management utilities (`esxcli`, `vim-cmd`, `power`, `shutdown`, `set`, `welcome`, `encrypt`)
- Command lines referencing VM-related files or extensions (`.vmdk`, `.vmem`, `.vmx`, etc.)
- Creation or reference to `PLAY_Readme.txt` in `/vmfs/volumes/` or `/root/`
- Use of flags such as `--skip-extension-check`, `--exempt-vm`, or `--encrypt-one-file`

These patterns are commonly seen in ransomware campaigns targeting virtualized workloads.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_command_line contains "esxcli"
    or actor_process_command_line contains "vim-cmd"
    or actor_process_command_line contains "power"
    or actor_process_command_line contains "shutdown"
    or actor_process_command_line contains "set"
    or actor_process_command_line contains "welcome"
    or actor_process_command_line contains "encrypt"
| filter actor_process_command_line contains "vm"
    or actor_process_command_line contains ".vmdk"
    or actor_process_command_line contains ".vmem"
    or actor_process_command_line contains ".vmsd"
    or actor_process_command_line contains ".vmsn"
    or actor_process_command_line contains ".vmx"
    or actor_process_command_line contains ".vmxf"
    or actor_process_command_line contains ".vswp"
    or actor_process_command_line contains ".vmss"
    or actor_process_command_line contains ".nvram"
    or actor_process_command_line contains ".vmtx"
    or actor_process_command_line contains ".log"
| filter actor_process_command_line contains "PLAY_Readme.txt"
    or actor_process_image_path contains "/vmfs/volumes/"
    or actor_process_image_path contains "/root/"
| filter actor_process_command_line contains "--skip-extension-check"
    or actor_process_command_line contains "--exempt-vm"
    or actor_process_command_line contains "--encrypt-one-file"
| fields agent_hostname, actor_process_image_path, actor_process_command_line, event_timestamp
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex SXIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process execution events from ESXi or virtualized workloads.
- **Required Artifacts:** Process execution logs, command line arguments, file paths.

---

## Considerations

- Investigate the process path, command line, and file access for evidence of VM targeting or encryption.
- Validate the user context and process responsible for suspicious activity.
- Correlate with other suspicious behaviors, such as mass VM shutdown or ransom note creation.

---

## False Positives

False positives may occur if:
- Legitimate administrative or backup operations use similar command lines or file paths.
- Internal IT or automation tools perform mass VM operations for benign reasons.

---

## Recommended Response Actions

1. Investigate the process tree, command line, and file access for malicious indicators.
2. Validate the legitimacy of the tool or script and its source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1496 – Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: T1561.002 – Disk Wipe: Logical Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1202 – Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)
- [#StopRansomware: Play Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-10 | Initial Detection | Created hunt query to detect Play ransomware ESXi targeting and VM encryption               |
