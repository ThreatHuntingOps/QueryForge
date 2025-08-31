# Threat Hunting Hypothesis - DarkCloud

## Source
- **Threat Intelligence:** [Unveiling a New Variant of the DarkCloud Campaign](https://www.fortinet.com/blog/threat-research/unveiling-a-new-variant-of-the-darkcloud-campaign)
- **Date:** August 2025
  
## Hypothesis Statement
One or more Windows endpoints in our environment have been compromised by the **new DarkCloud information‑stealer variant** after a phishing email delivered a **RAR attachment with no message body**, leading to execution of `wscript.exe` running a **.js** file that spawned **PowerShell with an encoded command** to **download a JPEG and reflectively load an encrypted, fileless .NET DLL** (masquerading as a Task Scheduler module), resulting in **credential, payment data, and email contact exfiltration**.

## Why This Hypothesis (Intelligence-Based Rationale)
FortiGuard Labs reported a July–August 2025 DarkCloud campaign that:
- Uses **phishing emails with RAR attachments** (often with no body) as the initial lure.
- Executes **obfuscated JavaScript** that **decodes and launches PowerShell**.
- **Loads an encrypted, fileless .NET DLL**, presented as a **Task Scheduler** component.
- Focuses on **stealing credentials, payment data, and contacts** from Windows systems.

_Source: FortiGuard Labs — “Unveiling a New Variant of the DarkCloud Campaign,” Aug 7, 2025._

## What Makes It Testable (Key Observables)
- **Email telemetry**
  - Inbound emails with **RAR attachments**; **empty/near-empty bodies**; “urgent quote” or similar lures.
- **Process lineage (EDR)**
  - `wscript.exe` → `.js` in user-writeable paths (e.g., Downloads, Temp) → `powershell.exe` with **`-EncodedCommand`** / **`-ExecutionPolicy Bypass`**.
- **PowerShell logs**
  - Base64-encoded payloads; network calls; in‑memory assembly loading (e.g., `Reflection.Assembly::Load` patterns).
- **Network/DNS**
  - HTTP/HTTPS GETs where response **Content-Type is `image/jpeg`** followed by no corresponding file write; short burst to new/low‑reputation domains.
- **Memory/Module telemetry**
  - In‑memory **.NET** module without backing file; strings or API usage suggesting **Task Scheduler** masquerade.
- **Exfil/collection**
  - Access to browser password stores, email clients/contacts, payment/auto‑fill data; outbound beacons post‑collection.

## Data Sources to Query
- Secure email gateway / M365: message trace, attachment types, body length.
- EDR/XDR: process trees, command lines, script block logs, AMSI events.
- PowerShell: Event IDs 4103/4104 (Script Block), 4105/4106 (module), 4688 (proc), module logging if enabled.
- Proxy/Firewall/NetFlow: HTTP(S) metadata, MIME types, JA3/JA3S, domain age/reputation.
- Memory sensors/DFIR: in‑memory module listings, .NET CLR activity.
- DLP/egress controls: anomalous uploads.

## Decision Criteria
- **Confirm** hypothesis if ≥3 of the following align on the same host/user and time window:
  1. Email with **RAR** attachment and minimal body.
  2. `wscript.exe` → `.js` → `powershell.exe` with **encoded** command.
  3. Network fetch of **JPEG** followed by **in‑memory .NET** load (no file on disk).
  4. Evidence of **credential/contact/payment data** access or exfiltration.
- **Refute** if process/network artifacts are benign (e.g., sanctioned script), attachments were blocked, or memory analysis shows no in‑memory DLL/collection behavior.

## Hunt Notes / Next Steps
- Prioritize **high-risk users** (finance, customer support, shared mailboxes).
- Timebox initial hunt to **July 1–present**; expand as needed.
- If indicators are found, **isolate host**, collect triage (EDR snapshot, PowerShell logs, net captures), and initiate **credential reset & containment** playbook.
