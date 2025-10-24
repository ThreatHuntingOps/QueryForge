# Password-Protected Binary Execution with Argument Pattern

#### Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** High

#### Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Qilin-PasswordProtected
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

#### Hunt Analytics

This hunt detects Qilin ransomware execution by identifying processes launched with a `-password` command-line argument, a required parameter for Qilin's password-protected execution mechanism. The detection also looks for additional Qilin-specific arguments (`-spread`, `-timer`, `-safe`, `-no-destruct`) that indicate ransomware behavior. When multiple Qilin-specific arguments are present and/or the binary is running from a suspicious location (not under `C:\Windows\` or `C:\Program Files`), the confidence is high.

Detected behaviors include:

- Process creation events containing `-password` on the command line
- Presence of additional Qilin indicators: `-spread`, `-timer`, `-safe`, `-no-destruct`
- Suspicious execution locations (not in `C:\Windows\` or `C:\Program Files`)

This is a high-confidence initial detection point for Qilin family ransomware when multiple indicators align.

---

#### ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion     | T1140       | -            | Deobfuscate/Decode Files or Information       |
| TA0002 - Execution           | T1059.001   | -            | Command and Scripting Interpreter: PowerShell |

---

#### Hunt Query Logic

This query searches Windows process start events for binaries launched with a `-password` argument and then derives additional signal-strengthening fields when other Qilin-specific arguments are present. It also flags binaries executing from locations outside of common system directories to increase confidence.

- Required: command line contains `-password`
- Additional indicators: `-spread`, `-timer`, `-safe`, `-no-destruct`
- Suspicious location if not under `C:\Windows\` or `C:\Program Files`
- Produces categorical fields (`qilin_arg_class`, `detection_category`, `risk_label`) as strings to avoid numeric/arithmetic operations in the query environment

---

#### Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Qilin ransomware — password-protected execution (translated to CQL)
| #repo="base_sensor" event_platform="Win"

// Limit to process start events
| #event_simpleName="ProcessRollup2"

// Initialize boolean/string flags (defaults)
| has_password_arg := "false"
| has_spread_arg := "false"
| has_timer_arg := "false"
| has_safe_arg := "false"
| has_no_destruct_arg := "false"
| in_windows_dir := "false"
| in_program_files := "false"
| suspicious_location := "false"
| addl_arg_any1 := "n"
| addl_arg_any2 := "n"
| addl_arg_pair1 := "n"
| addl_arg_any := "n"
| qilin_arg_class := "1"
| detection_category := "Password-Protected Execution"
| risk_label := "75"
| severity_key := "1"

// Phase 1: Required arg - look for "-password" (case-insensitive)
| #event_simpleName="ProcessRollup2" and CommandLine=/-password\b/i | has_password_arg := "true"

// Phase 2: Additional Qilin args
| #event_simpleName="ProcessRollup2" and CommandLine=/-spread\b/i        | has_spread_arg := "true"
| #event_simpleName="ProcessRollup2" and CommandLine=/-timer\b/i         | has_timer_arg := "true"
| #event_simpleName="ProcessRollup2" and CommandLine=/-safe\b/i          | has_safe_arg := "true"
| #event_simpleName="ProcessRollup2" and CommandLine=/-no-destruct\b/i   | has_no_destruct_arg := "true"

// Phase 3: Suspicious location helpers (case-insensitive checks against image path/name)
| #event_simpleName="ProcessRollup2" and ImageFileName=/c:\\\\windows\\\\/i      | in_windows_dir := "true"
| #event_simpleName="ProcessRollup2" and ImageFileName=/c:\\\\program files/i    | in_program_files := "true"

// Determine suspicious_location: image path exists and not in Windows or Program Files
| ImageFileName!="" and in_windows_dir="false" and in_program_files="false" | suspicious_location := "true"

// Correlation: require -password arg
| has_password_arg="true"

// Enrichment without numeric arithmetic — derive additional-arg buckets as strings
| (has_spread_arg="true" or has_timer_arg="true") | addl_arg_any1 := "y"
| (has_safe_arg="true" or has_no_destruct_arg="true") | addl_arg_any2 := "y"
| (addl_arg_any1="y" and addl_arg_any2="y") | addl_arg_pair1 := "y"
| (addl_arg_any1="y" or addl_arg_any2="y") | addl_arg_any := "y"

// Qilin arg class (string): "1", "2", "3plus"
| addl_arg_any="y" | qilin_arg_class := "2"
| addl_arg_pair1="y" | qilin_arg_class := "3plus"

// detection_category (strings only)
| qilin_arg_class="3plus" | detection_category := "Qilin Ransomware (High Confidence)"
| qilin_arg_class="2"     | detection_category := "Potential Qilin Ransomware"

// risk_label (strings only, mirrors your numeric intent)
| qilin_arg_class="3plus" and suspicious_location="true"  | risk_label := "100"
| qilin_arg_class="3plus" and suspicious_location!="true" | risk_label := "95"
| qilin_arg_class="2"     and suspicious_location="true"  | risk_label := "90"
| qilin_arg_class="2"     and suspicious_location!="true" | risk_label := "85"
| qilin_arg_class!="2" and qilin_arg_class!="3plus"       | risk_label := "75"

// severity_key for ordering (strings)
| qilin_arg_class="3plus" and suspicious_location="true"  | severity_key := "5"
| qilin_arg_class="3plus" and suspicious_location!="true" | severity_key := "4"
| qilin_arg_class="2"     and suspicious_location="true"  | severity_key := "3"
| qilin_arg_class="2"     and suspicious_location!="true" | severity_key := "2"
| qilin_arg_class!="2" and qilin_arg_class!="3plus"       | severity_key := "1"

// Final projection (string/boolean outputs only)
| select([
    @timestamp,
    aid,
    ComputerName,
    UserName,
    ImageFileName,
    ImageFilePath,
    CommandLine,
    has_password_arg,
    has_spread_arg,
    has_timer_arg,
    has_safe_arg,
    has_no_destruct_arg,
    suspicious_location,
    qilin_arg_class,
    detection_category,
    risk_label,
    severity_key,
    #event_simpleName
  ])
| sort([severity_key, @timestamp], order=desc)
```

---

#### Data Sources

| Provider                 | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component         |
|-------------------------|-----------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon      | base_sensor: ProcessRollup2 (process telemetry)          | Process            | Process Creation       |

---

#### Execution Requirements

- **Required Permissions:** Ability to execute a binary on Windows endpoints (local or remote execution). If the ransomware spawns child PowerShell processes the query also captures those indicators via command-line analysis.  
- **Required Artifacts:** Process creation logs with full command-line arguments and process image path information.

---

#### Considerations

- The `-password` flag is a specific behavior of Qilin's password-protected execution; however, some legitimate administrative tools or custom scripts could also use a `-password` argument.  
- Increase confidence by correlating with file encryption activity, creation of ransom notes, mass file modifications, or network indicators such as C2 callbacks.
- Check whether the binary is signed, the parent process is suspicious (e.g., MS Office spawning unknown EXE), and whether the endpoint has recent file I/O anomalies.

---

#### False Positives

False positives may occur when:

- Legitimate software or administrative scripts invoke a process with a `-password` argument for benign configuration or automation tasks.
- Developers or automation systems run password-protected utilities during patching, imaging, or management tasks.

Mitigation: Validate the binary publisher, parent process, user context, and recent change control records before remediating.

---

#### Recommended Response Actions

1. Inspect the command line, process image path, parent process, and actor (user) context for the event.
2. Query for related activity from the same host or user: additional process starts, file system modifications, creation of ransom notes, or high-rate file renames.
3. Collect memory and process artifacts for forensic analysis if the activity appears malicious.
4. Isolate the affected endpoint(s) from the network to prevent lateral spread if confirmed malicious.
5. Block or quarantine the binary hash(s) and related indicators in endpoint protection tooling and update detection rules to cover any additional IOCs.
6. Notify incident response and follow organizational ransomware playbooks for containment, eradication, and recovery.

---

#### References

- [MITRE ATT&CK: T1140 – Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

#### Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-23 | Initial Detection | Created hunt query to detect Qilin password-protected execution via `-password` and related arguments |
