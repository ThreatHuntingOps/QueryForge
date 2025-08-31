# SERPENTINE#CLOUD Threat Hunting Hypothesis

## Hypothesis Statement

**Threat actors are leveraging Cloudflare Tunnel infrastructure to deliver multi-stage, Python-based malware via phishing campaigns that use .lnk shortcut files disguised as documents. This infection chain results in in-memory execution of Donut-packed payloads, enabling stealthy remote access and persistence on endpoints within the environment.**

## Rationale

This hypothesis is based on recent threat intelligence from Securonix, which details:

- The use of Cloudflare Tunnel (trycloudflare[.]com) subdomains for hosting and delivering malicious payloads, making detection and attribution difficult due to trusted infrastructure and encrypted transport (WebDAV over HTTPS).
- Initial access via phishing emails containing ZIP archives with .lnk files masquerading as documents (e.g., invoices), which trigger a multi-stage infection chain involving batch, VBScript, and Python scripts.
- The final payload is a Python-based shellcode loader that executes Donut-packed PE payloads entirely in memory, evading traditional endpoint detection and leaving minimal forensic artifacts.
- Persistence is established through scripts placed in the Windows startup folder, and the malware demonstrates anti-forensics and stealth techniques throughout its lifecycle.

## Testable Predictions

- Unusual outbound connections to temporary *.trycloudflare[.]com subdomains, especially over WebDAV/HTTPS, from endpoints.
- Execution of .lnk files with hidden extensions and PDF icons, followed by the creation and execution of scripts in user profile directories (e.g., Contacts, Startup).
- Presence of Python processes (python.exe) running from non-standard directories, particularly shortly after .lnk file execution.
- In-memory-only payloads and process injection activity (e.g., Early Bird APC injection) involving python.exe or notepad.exe.
- Beaconing to known C2 domains/IPs associated with the campaign (e.g., nhvncpure[.]shop, duckdns[.]org, twilightparadox[.]com).

## Scope of the Hunt

- Focus on endpoints receiving phishing emails with ZIP attachments.
- Monitor for execution of .lnk files and subsequent script activity in user directories.
- Analyze network traffic for connections to Cloudflare Tunnel subdomains and known C2 infrastructure.
- Investigate process trees for python.exe and notepad.exe spawned from unusual locations or with suspicious command-line arguments.

---

*Based on threat intelligence from [Securonix Threat Research](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/), June 2025.*
