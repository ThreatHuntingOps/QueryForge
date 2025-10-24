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

This XQL query searches Windows process start events for binaries launched with a `-password` argument and then derives additional signal-strengthening fields when other Qilin-specific arguments are present. It also flags binaries executing from locations outside of common system directories to increase confidence.

- Required: command line contains `-password`
- Additional indicators: `-spread`, `-timer`, `-safe`, `-no-destruct`
- Suspicious location if not under `C:\Windows\` or `C:\Program Files`
- Produces categorical fields (`qilin_arg_class`, `detection_category`, `risk_label`) as strings to avoid numeric/arithmetic operations in the query environment

---

#### Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR / XSIAM

```xql
// Hunt for Qilin ransomware password‑protected execution
// T1140 - Deobfuscate/Decode Files or Information
// Strict string/boolean only: no numeric fields or arithmetic to avoid concat errors

config case_sensitive = false
| dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter event_type = PROCESS and event_sub_type = ENUM.PROCESS_START

// Phase 1: Required arg
| alter has_password_arg = if(action_process_image_command_line != null and action_process_image_command_line contains "-password", true, false)

// Phase 2: Additional Qilin args
| alter has_spread_arg = if(action_process_image_command_line != null and action_process_image_command_line contains "-spread", true, false)
| alter has_timer_arg  = if(action_process_image_command_line != null and action_process_image_command_line contains "-timer", true, false)
| alter has_safe_arg   = if(action_process_image_command_line != null and action_process_image_command_line contains "-safe", true, false)
| alter has_no_destruct_arg = if(action_process_image_command_line != null and action_process_image_command_line contains "-no-destruct", true, false)

// Phase 3: Suspicious location helpers, then final flag
| alter in_windows_dir = if(action_process_image_path != null and action_process_image_path contains "c:\windows\", true, false)
| alter in_program_files = if(action_process_image_path != null and action_process_image_path contains "c:\program files", true, false)
| alter suspicious_location = if(action_process_image_path != null and (in_windows_dir = false and in_program_files = false), true, false)

// Correlation: must have -password
| filter has_password_arg = true

// Enrichment without numbers: derive count class and severity as strings
// Count class: "3plus" if 2 or more additional args are present; "2" if exactly one; "1" if none
| alter addl_arg_any1 = if(has_spread_arg = true or has_timer_arg = true, "y", "n")
| alter addl_arg_any2 = if(has_safe_arg = true or has_no_destruct_arg = true, "y", "n")
| alter addl_arg_pair1 = if(addl_arg_any1 = "y" and addl_arg_any2 = "y", "y", "n")        // at least 2 different buckets hit
| alter addl_arg_any = if(addl_arg_any1 = "y" or addl_arg_any2 = "y", "y", "n")

| alter qilin_arg_class = "1"
| alter qilin_arg_class = if(addl_arg_any = "y", "2", qilin_arg_class)
| alter qilin_arg_class = if(addl_arg_pair1 = "y", "3plus", qilin_arg_class)

// detection_category purely strings
| alter detection_category = "Password-Protected Execution"
| alter detection_category = if(qilin_arg_class = "2", "Potential Qilin Ransomware", detection_category)
| alter detection_category = if(qilin_arg_class = "3plus", "Qilin Ransomware (High Confidence)", detection_category)

// risk_label purely strings (mirrors your numeric intent but as strings)
// Base: 75; 2-arg: 85; 2-arg+suspicious: 90; 3plus: 95; 3plus+suspicious: 100
| alter risk_label = "75"
| alter risk_label = if(qilin_arg_class = "2", "85", risk_label)
| alter risk_label = if(qilin_arg_class = "2" and suspicious_location = true, "90", risk_label)
| alter risk_label = if(qilin_arg_class = "3plus", "95", risk_label)
| alter risk_label = if(qilin_arg_class = "3plus" and suspicious_location = true, "100", risk_label)

// severity_key for sorting (string that sorts in desired order)
// 5=100(highest), 4=95, 3=90, 2=85, 1=75. All values are strings.
| alter severity_key = "1"
| alter severity_key = if(qilin_arg_class = "2", "2", severity_key)
| alter severity_key = if(qilin_arg_class = "2" and suspicious_location = true, "3", severity_key)
| alter severity_key = if(qilin_arg_class = "3plus", "4", severity_key)
| alter severity_key = if(qilin_arg_class = "3plus" and suspicious_location = true, "5", severity_key)

// Output: project only booleans/strings
| fields _time,
         agent_hostname,
         actor_effective_username,
         action_process_image_name,
         action_process_image_path,
         action_process_image_command_line,
         has_password_arg,
         has_spread_arg,
         has_timer_arg,
         has_safe_arg,
         has_no_destruct_arg,
         suspicious_location,
         qilin_arg_class,
         detection_category,
         risk_label
```

---

#### Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |

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
