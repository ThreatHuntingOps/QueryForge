# KongTuke FileFix & Interlock RAT Variant Threat Hunting Hypothesis

## Hypothesis Statement

There is a high likelihood that the environment contains evidence of compromise by the new Interlock RAT PHP variant, delivered via KongTuke (LandUpdate808) FileFix web-inject campaigns. This threat leverages PowerShell to execute PHP-based payloads from non-standard locations, establishes persistence, performs automated and interactive reconnaissance, and maintains command and control via Cloudflare Tunnel infrastructure.

## Rationale

This hypothesis is based on recent threat intelligence from [The DFIR Report](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/), which details:

- The use of compromised websites to deliver malicious JavaScript, prompting users to execute PowerShell commands that download and run a PHP-based RAT from the user's AppData directory.
- The RAT's immediate system profiling, privilege checking, and exfiltration of system data via PowerShell.
- Establishment of persistence through Windows Registry Run keys.
- Use of Cloudflare Tunnel (trycloudflare.com) for resilient C2, with hardcoded fallback IPs.
- Evidence of both automated and hands-on-keyboard discovery, and lateral movement via RDP.

## Testable Indicators

- Presence of suspicious PowerShell execution spawning `php.exe` from AppData with ZIP extension enabled and non-standard config file locations.
- Registry Run keys referencing `php.exe` in AppData.
- Outbound connections to known trycloudflare.com subdomains or fallback IPs (e.g., 64.95.12.71, 184.95.51.165).
- System and network reconnaissance commands executed via PowerShell or cmd.exe.
- Evidence of RDP-based lateral movement following initial compromise.

## Purpose

This hypothesis will guide targeted threat hunting for:

- Malicious PowerShell and PHP activity in user AppData directories.
- Persistence mechanisms related to Interlock RAT.
- C2 communications leveraging Cloudflare Tunnel and fallback IPs.
- Reconnaissance and lateral movement behaviors consistent with the described TTPs.

---

*Based on threat intelligence published by The DFIR Report, July 2025.*
