# Qilin Ransomware Threat Hunting Hypothesis Statement

Qilin ransomware (also known as Agenda) is actively executing within our network, leveraging its unique multi-stage attack chain which includes password-protected execution, volume shadow copy deletion, event log clearing, registry persistence with asterisk-prefixed Run keys, service termination, and selective file encryption with ChaCha20/AES algorithms. Initial access is likely through spear-phishing, and the threat may have already progressed to encryption phase given recent suspicious file modifications or network behaviors consistent with Qilin's TTPs.

#### Threat Intelligence Source

- **Source**: [AhnLab ASEC - Analysis on the Qilin Ransomware](https://asec.ahnlab.com/en/90497/)
- **Date**: September 30, 2025
- **Key Findings**:
  - Qilin uses a `-password` argument for execution control and SHA-256 comparison
  - Deletes volume shadow copies using `vssadmin`, `wmic`, and `net` commands
  - Clears Windows event logs via PowerShell (`EventLogSession.ClearLog`)
  - Establishes persistence using registry Run keys with `*XXXXXX` value names (enables Safe Mode execution)
  - Terminates over 50 critical services and processes (backup, DB, email, VM, security tools)
  - Encrypts files using AES-256 or ChaCha20 with RSA-4096 wrapped keys
  - Creates `README-RECOVER-<ext>.txt` ransom notes and `QLOG` folders
  - Self-deletion unless `-no-destruct` is used

#### Purpose of Hunt Campaign 

To proactively detect and confirm the presence of Qilin ransomware at any stage of its attack lifecycle within our environment, from initial execution to full encryption, using correlated endpoint telemetry and behavioral analytics.

#### Testable Indicators

1. **Execution Phase**:
   - Processes launched with `-password` argument
   - Use of additional Qilin arguments (`-spread`, `-timer`, `-safe`, etc.)

2. **Pre-Encryption Preparation**:
   - Bulk execution of `vssadmin delete shadows`, `wmic service where name='vss' call ChangeStartMode`, `net start/stop vss`
   - PowerShell processes invoking `EventLogSession.ClearLog()` and `Get-WinEvent`
   - Termination of 10+ critical services/processes (e.g., `sql`, `veeam`, `exchange`, `vmms`, `sophos`)

3. **Persistence**:
   - Registry `SetValue` events in `CurrentVersion\Run` with value names matching `^\*[A-Za-z0-9]{6}$`

4. **Lateral Movement**:
   - PsExec execution with `-spread` argument
   - Outbound SMB (port 445) connections from hosts running PsExec

5. **Impact (Encryption)**:
   - Creation of files with random 10+ character extensions
   - Creation of `README-RECOVER-*.txt` ransom notes
   - Creation of `QLOG` folders in `Temp` directories
   - Desktop wallpaper changes by non-system processes

#### Recommended Data Sources

- Endpoint Detection and Response (EDR) logs (process creation, registry, file, network)
- Windows Event Logs (System, Security, Application)
- Network flow logs (especially SMB traffic on port 445)
- PowerShell script block logging (if enabled)

#### Recommended Response Actions if Confirmed

1. Immediately isolate affected hosts and preserve for forensic analysis
2. Block known Qilin IOCs (file hashes, registry keys, network domains)
3. Review backup integrity and off-host storage for signs of compromise
4. Notify incident response team and initiate ransomware playbook
5. Conduct retrospective analysis across all endpoints for signs of early-stage activity

#### Version History

| Version | Date       | Notes                          |
|---------|------------|--------------------------------|
| 1.0     | 2025-10-23 | Initial hypothesis based on AhnLab Qilin report |
