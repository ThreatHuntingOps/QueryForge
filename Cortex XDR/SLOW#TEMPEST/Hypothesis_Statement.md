# Hypothesis Statement: SLOW#TEMPEST Malware Obfuscation

## Purpose
Guide a targeted threat hunt for advanced malware leveraging SLOW#TEMPEST obfuscation techniques, as described by Unit 42, to ensure early detection and mitigation within the organization.

## Hypothesis

Adversaries leveraging SLOW#TEMPEST malware are present in the environment, using advanced control flow graph (CFG) obfuscation and obfuscated function calls (e.g., dynamic jumps, indirect CALL RAX instructions) to evade static and dynamic analysis, and are deploying payloads via DLL side-loading through legitimate signed binaries.

## Rationale

- Recent threat intelligence from Unit 42 (July 2025) shows SLOW#TEMPEST campaigns actively using ISO-based delivery, DLL side-loading, and sophisticated anti-analysis techniques to bypass detection.
- These techniques are designed to defeat both static and dynamic analysis, making traditional detection methods less effective.
- The presence of such obfuscation patterns (dynamic jumps, indirect function calls, DLL side-loading) in telemetry or EDR logs may indicate undetected SLOW#TEMPEST activity.

## Testability

- Hunt for execution of legitimate signed binaries (e.g., DingTalk.exe) loading suspicious DLLs (e.g., zlibwapi.dll) from unusual directories.
- Analyze process memory and execution traces for evidence of dynamic jump instructions (JMP RAX) and indirect function calls (CALL RAX) within loaded modules.
- Search for ISO file mounts followed by DLL side-loading activity.
- Correlate findings with known SLOW#TEMPEST indicators of compromise (IOCs) and behavioral patterns.

---

**References:**
- [Unit 42: Evolving Tactics of SLOW#TEMPEST: A Deep Dive Into Advanced Malware Techniques](https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/)
