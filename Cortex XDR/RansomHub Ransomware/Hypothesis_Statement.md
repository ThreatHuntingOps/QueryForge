# Threat Hunting Hypothesis: RDP Password Spray Leading to RansomHub Deployment

## Background

This hypothesis is based on threat intelligence from [The DFIR Report: "Hide Your RDP: Password Spray Leads to RansomHub Deployment" (June 30, 2025)](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/). The report details a real-world intrusion where attackers gained initial access via password spraying against an exposed RDP server, followed by credential harvesting, lateral movement, data exfiltration, and deployment of RansomHub ransomware.

## Hypothesis Statement

**If externally accessible RDP servers exist in the environment, then threat actors may attempt password spray attacks to gain initial access, followed by credential harvesting (using tools like Mimikatz and Nirsoft), lateral movement via RDP and SMB, data exfiltration using Rclone over SFTP, and ultimately deploy RansomHub ransomware or similar payloads.**

## Purpose

This hypothesis will guide the threat hunt to:
- Detect evidence of password spray attacks against RDP endpoints.
- Identify use of credential harvesting tools (Mimikatz, Nirsoft).
- Track lateral movement via RDP and SMB.
- Detect data exfiltration activity (Rclone, SFTP).
- Identify ransomware deployment and related impact activities.

## Characteristics

- **Specific and actionable:** Focuses on RDP password spray as initial access, with clear follow-on attacker behaviors.
- **Based on threat intelligence:** Directly informed by a recent, real-world intrusion case.
- **Testable:** Can be validated through log analysis (Windows Event Logs, Sysmon, IDS/IPS. NDR), detection of specific tools, and network monitoring.

## Testable Questions

- Are there signs of failed and successful RDP logins from external IPs (Event ID 4625/4624)?
- Is there evidence of credential dumping tools (Mimikatz, Nirsoft) being executed (Event ID 4662, 5379, Sysmon Event 10)?
- Are there patterns of lateral movement via RDP (LogonType 10) or SMB file transfers?
- Is there outbound SFTP traffic (port 443) from file servers, especially involving Rclone?
- Are there indications of ransomware binaries (e.g., amd64.exe) being dropped and executed, shadow copy deletions, or event log clearing?

## Reference

- [The DFIR Report: Hide Your RDP: Password Spray Leads to RansomHub Deployment (June 30, 2025)](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)
