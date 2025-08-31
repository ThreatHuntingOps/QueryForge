# Hypothesis Statement: Anubis Ransomware Threat Hunt

## Hypothesis Statement

**If Anubis ransomware is present in the environment, then there will be observable evidence of both file encryption and destructive file wiping activity, including the use of unique command-line parameters (such as `/WIPEMODE`, `/KEY=`, `/elevated`), attempts to delete shadow copies, privilege escalation prompts, and the creation of ransom notes and custom icons/wallpapers.**

## Rationale

This hypothesis is based on threat intelligence from [Trend Micro's analysis of Anubis ransomware](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html), which highlights the following:

- Anubis is a Ransomware-as-a-Service (RaaS) operation that combines file encryption with a destructive file-wiping feature, making recovery difficult or impossible.
- The ransomware uses specific command-line parameters (e.g., `/WIPEMODE`, `/KEY=`, `/elevated`, `/PFAD=`, `/PATH=`) to control its behavior, including privilege escalation and file wiping.
- It attempts to delete Volume Shadow Copies using `vssadmin delete shadows /for=norealvolume /all /quiet` to inhibit system recovery.
- Anubis displays interactive privilege escalation prompts and can relaunch itself with elevated rights.
- The malware drops custom icons and wallpaper images, changes file extensions to `.anubis.`, and creates ransom notes named `RESTORE FILES.html`.
- The presence of ECIES-based encryption routines and references to related Go packages (e.g., EvilByte, Prince) are also indicators.

## Testability

This hypothesis can be tested by:
- Searching for process executions with Anubis-specific command-line parameters in endpoint telemetry.
- Detecting file write events for ransom notes, custom icons, wallpapers, and files with the `.anubis.` extension.
- Identifying shadow copy deletion commands and privilege escalation attempts in process logs.
- Correlating these activities with known Anubis TTPs and IOCs.

## Purpose

This hypothesis guides the threat hunt to focus on the unique dual-threat behaviors of Anubis ransomware, ensuring that detection efforts are targeted, actionable, and efficient.

---

**Reference:**
- [Anubis: A Closer Look at an Emerging Ransomware with Built-in Wiper (Trend Micro, 2025)](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html)
