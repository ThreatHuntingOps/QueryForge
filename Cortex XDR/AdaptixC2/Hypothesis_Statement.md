# Hypothesis Statement: AdaptixC2 Post-Exploitation Threat Hunt

## Hypothesis
Adversaries leveraging the AdaptixC2 post-exploitation framework may be operating within the environment by utilizing **PowerShell-based loaders**, **registry persistence**, **DLL hijacking**, and **non-standard HTTPS beaconing** to maintain covert access, execute payloads in-memory, and exfiltrate data.

## Purpose
This hypothesis guides the hunt toward identifying signs of AdaptixC2 activity by focusing on key behaviors detailed in [Unit42 AdaptixC2 Threat Intelligence](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/). It ensures hunts are **targeted and efficient** by narrowing scope to high-fidelity TTPs commonly associated with the framework’s operations.

## Rationale
- **Threat Intelligence:** Unit42 identified AdaptixC2 operators using obfuscated PowerShell (`FromBase64String`, `Invoke-RestMethod`) for in-memory execution.
- **Persistence:** Registry Run keys and DLL hijacking in the `Templates` directory provide resilience across reboots.
- **Evasion:** Encoded PowerShell commands (`-enc`) hinder static detection.
- **Command and Control (C2):** HTTPS beaconing over **ports 443/4443/8443** and use of suspicious TLDs or misleading domains (e.g., `systemware`, `flareaxe`) indicates advanced infrastructure obfuscation.

## Testable Assumptions
- Hosts initiating **repeated outbound connections** to suspicious domains or non-standard TLS ports may be staging AdaptixC2 beaconing.
- **PowerShell executions** containing `FromBase64String`, `VirtualAlloc`, or `Invoke-RestMethod` may indicate shellcode loaders or payload retrieval.
- **Registry modifications** referencing `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` may point to persistence setups.
- **Suspicious DLLs** created in `AppData\Roaming\Microsoft\Windows\Templates\` may signal DLL hijacking attempts.
- **Encoded PowerShell usage (-enc)** alongside persistence techniques may signify evasion combined with long-term access attempts.

## Scope of Hunt
The hunt will target telemetry across:
- **Process execution logs** (PowerShell, reg.exe, encoded scripts)
- **File system activity** (DLL placement in Templates, Startup LNK persistence)
- **Registry changes** (Run key modifications)
- **Network activity** (C2 beaconing patterns, port/TLD anomalies)

## Expected Outcome
Confirmation or dismissal of AdaptixC2 activity within the environment based on identified telemetry and correlations. Findings will inform both **incident response actions** and **long-term detection engineering improvements**.
