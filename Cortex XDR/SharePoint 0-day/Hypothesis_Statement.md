# Threat Hunt Hypothesis: SharePoint 0-day (CVE-2025-53770) Mass Exploitation

## Hypothesis Statement

Adversaries are actively exploiting a chain of unauthenticated remote code execution (RCE) vulnerabilities in on-premises Microsoft SharePoint servers (CVE-2025-53770, CVE-2025-49704, CVE-2025-49706, and related CVEs), as observed in recent mass exploitation campaigns. Attackers leverage these flaws to upload and execute malicious ASPX webshells (e.g., `spinstall0.aspx`), exfiltrate cryptographic machine keys, and establish persistent access. The theft of these keys enables adversaries to craft valid, signed `__VIEWSTATE` payloads for ongoing, credential-less RCE—even after patching—unless keys are rotated. Recent intelligence highlights the use of multi-stage payloads, living-off-the-land binaries (LOLBins), and rapid lateral movement, with some campaigns deploying ransomware or data theft modules post-exploitation.

## Purpose

This hypothesis will guide a targeted threat hunt to identify evidence of exploitation, persistence mechanisms, cryptographic key exfiltration, and post-exploitation activity on SharePoint servers, enabling rapid detection and response to this evolving threat.

## Supporting Intelligence

**Vulnerabilities:**  
CVE-2025-53770, CVE-2025-49704, and CVE-2025-49706 allow unauthenticated attackers to upload and execute arbitrary ASPX files on vulnerable SharePoint servers. Microsoft and Unit 42 report that exploitation is widespread and ongoing.

**Observed TTPs:**  
Attackers use crafted POST requests to `/layouts/15/ToolPane.aspx` (and related endpoints), often with a `Referer` header set to `/layouts/SignOut.aspx` or `/layouts/settings.aspx`, to bypass authentication and drop webshells.  
Malicious ASPX files (e.g., `spinstall0.aspx`, `spkeydump.aspx`) are used to dump and exfiltrate cryptographic machine keys and other sensitive configuration data.  
Some campaigns chain these exploits with additional LOLBins (e.g., `certutil`, `powershell`) for further payload delivery, credential dumping, or lateral movement.

**Persistence:**  
Exfiltrated machine keys allow attackers to generate valid, signed `__VIEWSTATE` payloads for persistent RCE, even after patching, unless keys are rotated.  
Recent attacks have also deployed scheduled tasks and registry modifications for additional persistence.

**Indicators:**  
Known IOCs include specific file paths (`/layouts/15/spinstall0.aspx`, `/layouts/15/spkeydump.aspx`), suspicious user agents (e.g., `python-requests`, `curl`), and attacker IP addresses (see referenced blogs for latest IOCs).  
Unit 42 and Microsoft report increased outbound traffic to attacker-controlled infrastructure, often over uncommon ports or via encrypted channels.

## Testable Questions

- Are there unauthorized or suspicious ASPX files (e.g., `spinstall0.aspx`, `spkeydump.aspx`) present in SharePoint server directories?
- Do IIS logs show POST requests to `/layouts/15/ToolPane.aspx` (or similar endpoints) with a `Referer` of `/layouts/SignOut.aspx` or `/layouts/settings.aspx` and no authenticated user?
- Are there outbound connections or data exfiltration attempts from SharePoint servers, especially involving cryptographic material or configuration files?
- Have any cryptographic machine keys been accessed, dumped, or rotated unexpectedly?
- Are there signs of persistence (e.g., scheduled tasks, registry changes) or lateral movement originating from SharePoint servers?
- Is there evidence of LOLBin usage (e.g., `certutil`, `powershell`) or post-exploitation payloads (e.g., ransomware, credential dumpers)?

## Data Sources

- IIS and SharePoint server logs
- XDR telemetry (e.g., Cortex XDR)
- File system integrity monitoring
- Network traffic logs (for exfiltration attempts and C2)
- Windows Event Logs (process creation, PowerShell activity)
- Registry and scheduled task monitoring

## References

- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)
- [Analyzing Sharepoint Exploits (CVE-2025-53770, CVE-2025-53771)](https://isc.sans.edu/diary/Analyzing+Sharepoint+Exploits+CVE202553770+CVE202553771/32138)
