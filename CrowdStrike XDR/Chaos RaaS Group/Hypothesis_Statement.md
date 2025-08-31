
# Threat Hunting Hypothesis: Chaos RaaS Group Activity

### Based on Threat Intelligence From: 
[Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Hypothesis Statement

A threat actor, likely the Chaos ransomware group or an affiliate exhibiting TTPs similar to BlackSuit/Royal, has gained initial access to the environment through a social engineering campaign that leverages Microsoft Quick Assist. The actor is establishing persistence and command and control using legitimate Remote Monitoring and Management (RMM) software, is performing discovery and lateral movement with living-off-the-land binaries (LOLbins) and tools like Impacket, and is exfiltrating data using a legitimate file synchronization tool (GoodSync) masquerading as a native Windows process. This activity is a precursor to the final deployment of the Chaos ransomware.

## Supporting Evidence & Key TTPs

This hypothesis is based on the following techniques, tactics, and procedures (TTPs) identified in the Chaos RaaS campaign:

#### 1. Initial Access & Execution
*   **Social Engineering:** Actors use voice phishing (vishing) to convince a target to initiate a **Microsoft Quick Assist** (`msra.exe`) session, granting the actor initial remote access.
*   **Scripting:** Heavy use of **PowerShell** for environment preparation and command execution.
*   **Remote Execution:** Use of Impacket's `atexec` for remote command execution.

#### 2. Persistence & Defense Evasion
*   **Legitimate RMM Tools:** Installation of commercial RMM tools like **AnyDesk, ScreenConnect, Splashtop, OptiTune, or Syncro RMM** to maintain persistent access.
*   **Hidden Accounts:** Modification of the Windows Registry (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist`) to hide user accounts from the login screen.
*   **Defense Impairment:** Use of `wmic` to uninstall security applications and deletion of Volume Shadow Copies (`vssadmin delete shadows`) to inhibit recovery.

#### 3. Discovery & Lateral Movement
*   **Network Reconnaissance:** Execution of native discovery tools such as `ipconfig`, `nltest`, `net view`, `quser`, and `tasklist`.
*   **Lateral Movement:** Use of **Remote Desktop Protocol (RDP)** and **Impacket** (over SMB/WMI) to move across the network.

#### 4. Collection & Exfiltration
*   **Data Staging:** Use of a legitimate file synchronization tool, **GoodSync**, for data collection.
*   **Masquerading:** The exfiltration tool is often renamed to masquerade as a legitimate Windows process, such as `wininit.exe`.
*   **Exfiltration Channel:** Data is exfiltrated to an actor-controlled cloud storage location.

#### 5. Command and Control (C2)
*   **Encrypted Tunnels:** Use of **reverse SSH tunnels** for C2 communications, often over common ports like 443 to blend in with normal traffic. The observed actor C2 IP was `45[.]61[.]134[.]36`.

## Testable Hunt Queries & Data Sources

This hypothesis can be tested by querying the following data sources for evidence of the TTPs:

*   **Endpoint Detection & Response (EDR) / Process Logs:**
    *   Search for executions of `msra.exe` (Quick Assist) followed closely by network connections to unusual IPs or the execution of PowerShell scripts.
    *   Hunt for the installation or execution of non-standard RMM tools (AnyDesk, Splashtop, etc.).
    *   Query for command-line arguments containing `vssadmin delete shadows`, `wmic product where name=... call uninstall`, or `reg add ... SpecialAccounts`.
    *   Look for processes named `wininit.exe` that are not running from `%SystemRoot%\system32\` or that exhibit network activity consistent with file uploads (e.g., high-volume outbound traffic).

*   **Network Traffic / Firewall Logs:**
    *   Monitor for SSH traffic on non-standard ports (e.g., 443/TCP).
    *   Look for connections to known malicious IOCs, such as the IP address `45[.]61[.]134[.]36`.
    *   Analyze traffic patterns for large data uploads to unfamiliar cloud storage providers.

*   **Authentication / SIEM Logs:**
    *   Audit for password resets performed with `net.exe user ... /dom`.
    *   Correlate RDP authentication events with prior suspicious process executions on the source machine.
