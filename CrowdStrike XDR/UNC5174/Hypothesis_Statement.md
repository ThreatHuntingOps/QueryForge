# Threat Hunting Hypothesis: UNC5174 (Chinese Threat Actor) - SNOWLIGHT & VShell

## Hypothesis Statement

**There is a possibility that one or more Linux-based systems within our environment have been compromised by UNC5174, evidenced by the presence of fileless malware (VShell) loaded in memory via the SNOWLIGHT dropper, which establishes persistence through cron jobs or systemd/init.d services, and communicates with command and control (C2) infrastructure using WebSockets over suspicious domains such as `gooogleasia[.]com` (including subdomains like `vs.gooogleasia.com`) and `sex666vr[.]com`.**

---

## Rationale

This hypothesis is based on the following threat intelligence indicators and TTPs (Tactics, Techniques, and Procedures) from the Sysdig report:

- UNC5174 is actively targeting Linux systems using a malicious bash script that downloads and executes SNOWLIGHT and Sliver implants, and then loads VShell as a fileless payload in memory.
- Persistence is achieved by modifying crontab and/or creating systemd/init.d services for the dropped binaries.
- The malware communicates with C2 infrastructure using WebSockets, specifically over domains that impersonate legitimate brands (e.g., `gooogleasia[.]com`, `vs.gooogleasia.com`, `sex666vr[.]com`).
- The SNOWLIGHT dropper and VShell payload attempt to blend in by masquerading as legitimate system processes (e.g., `[kworker/0:2]`).
- The attack chain is unique in its use of fileless payloads, memory-only execution, and WebSocket-based C2, making it stealthy and difficult to detect with traditional file-based or signature-based methods.

---

## Testable Actions

To test this hypothesis, threat hunters should:

- Search for evidence of suspicious cron jobs or systemd/init.d services referencing binaries named `dnsloger`, `system_worker`, or similar, especially in `/usr/bin/` or `/tmp/`.
- Look for processes running as `[kworker/0:2]` or other suspiciously named processes that do not match legitimate kernel worker threads.
- Analyze network traffic for outbound WebSocket connections to the identified C2 domains and subdomains (e.g., `vs.gooogleasia.com:8443`, `sex666vr.com`).
- Investigate the use of `memfd_create` and `fexecve` syscalls, which may indicate fileless malware execution in memory.
- Check for the presence of the specific user-agent string `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` in outbound HTTP requests, as used by SNOWLIGHT.

---
