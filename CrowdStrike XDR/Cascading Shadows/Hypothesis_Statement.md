# Threat Hunting Hypothesis: Cascading Shadows - Phishing Campaign (AutoIt, Agent Tesla, RemcosRAT, XLoader)

## Hypothesis Statement

**There is a possibility that one or more systems within our environment have been compromised through a phishing campaign leveraging multi-stage delivery mechanisms involving malicious archive files (e.g., `.7z` with `.jse` files), PowerShell scripts, and AutoIt/.NET payloads, leading to the deployment of malware families like Agent Tesla, RemcosRAT, and XLoader.**

---

## Rationale

This hypothesis is based on Unit42’s findings:

- Phishing emails disguised as order/payment requests deliver malicious `.7z` archives containing `.jse` scripts.
- These scripts download PowerShell payloads containing Base64-encoded binaries.
- Attackers diverge paths by delivering either a .NET compiled executable or an AutoIt compiled executable, both of which inject malware into trusted system processes (`RegAsm.exe` or `RegSvcs.exe`).
- Final payloads include Agent Tesla variants, RemcosRAT, or XLoader malware.
- The campaign focuses on multi-stage evasion tactics over heavy obfuscation to bypass sandbox detection.

Source: [Unit42 – Cascading Shadows Attack Chain](https://unit42.paloaltonetworks.com/phishing-campaign-with-complex-attack-chain/)

---

## Testable Actions

To test this hypothesis, threat hunters should:

- Search email gateway and endpoint telemetry for `.7z` archives containing `.jse` files, especially related to fake order or payment communications.
- Detect execution of `.jse` scripts followed by suspicious PowerShell activities.
- Monitor PowerShell decoding and execution of Base64 payloads.
- Hunt for process injection activities targeting `RegAsm.exe` and `RegSvcs.exe`.
- Look for behaviors associated with Agent Tesla, RemcosRAT, or XLoader post-compromise activities (e.g., credential theft, remote access).

---
