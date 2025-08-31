# Threat Hunting Hypothesis: Interlock Ransomware

## Hypothesis Statement

**If**:  
An organization’s environment includes Windows or Linux virtual machines, and users have access to web browsers and cloud storage services,

**Then**:  
There is a measurable risk that Interlock ransomware actors may have gained initial access via drive-by downloads from compromised legitimate websites or through the “ClickFix” social engineering technique, leading to the deployment of remote access trojans (RATs), credential stealers, and subsequent double-extortion ransomware activity targeting virtual machines and cloud storage.

## Rationale

- **Threat Intelligence Basis**:  
  According to [CISA AA25-203A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a), Interlock ransomware actors have recently targeted organizations in North America and Europe using drive-by downloads and social engineering (ClickFix) to deliver malicious payloads, with a focus on encrypting VMs and exfiltrating data from cloud storage.
- **Observed TTPs**:  
  - Initial access via compromised websites and fake software/security updates.
  - Use of PowerShell scripts for persistence, reconnaissance, and credential theft.
  - Lateral movement using stolen credentials and remote access tools (e.g., AnyDesk, PuTTY).
  - Data exfiltration to Azure blobs and via WinSCP.
  - Double extortion: encryption of VMs and threats to leak exfiltrated data.
- **Industry Trends**:  
  - Increased targeting of virtualized environments and cloud storage.
  - Use of legitimate remote access and file transfer tools for persistence and exfiltration.

## Testable Questions

- Are there signs of drive-by download activity or execution of suspicious PowerShell scripts on endpoints, especially VMs?
- Have any users executed files or scripts matching known Interlock IOCs (e.g., `cht.exe`, `klg.dll`, `conhost.exe`)?
- Is there evidence of abnormal use of remote access tools (AnyDesk, PuTTY) or cloud storage utilities (Azure Storage Explorer, AzCopy) in the environment?
- Are there indications of credential theft, lateral movement, or unauthorized access to cloud storage resources?
- Have any files been encrypted with `.interlock` or `.1nt3rlock` extensions, or have ransom notes titled `!__README__!.txt` appeared?

## Scope and Direction

This hunt will focus on:
- Endpoint telemetry (PowerShell, process creation, file writes)
- Web proxy and DNS logs (drive-by downloads, access to suspicious domains)
- Authentication and access logs (lateral movement, credential use)
- Cloud storage access and data transfer logs
- Detection of known IOCs and TTPs associated with Interlock ransomware

---

*Reference: [CISA AA25-203A: #StopRansomware: Interlock](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a)*
