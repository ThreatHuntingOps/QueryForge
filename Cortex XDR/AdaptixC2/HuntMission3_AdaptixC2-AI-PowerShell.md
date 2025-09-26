# Detection of AdaptixC2 AI-Generated PowerShell Script Indicators

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-AdaptixC2-AI-PowerShell  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low-Medium  

---

## Hunt Analytics

This hunt detects **AI-authored or AI-assisted PowerShell scripts** leveraged by AdaptixC2 operators.  
Unit42 highlights that AdaptixC2 experimented with **automatically generated PowerShell loaders**, which exhibit **non-human coding patterns**, such as:

- Artificially numbered comments (`// [1], // [2], // [3]`)  
- Progress or completion markers (`[✔], [✓], [DONE]`) like AI code annotations  
- Verbose instructional inline comments (`# Download`, `# Execute`, `# Persistence`, `# Decode`)  
- Natural-language script block phrases: `"Download and decode", "Persistence set"`  

These artifacts strongly suggest AI-based script generation tools, deviating from attacker tradecraft.

---

## ATT&amp;CK Mapping

| Tactic(s)           | Technique ID | Technique Name                                       |
|---------------------|--------------|-----------------------------------------------------|
| Execution           | T1059.001    | Command and Scripting Interpreter: PowerShell       |
| Defense Evasion     | T1036.005    | Masquerading: Match Legitimate Names or Comments    |
| Defense Evasion     | T1027        | Obfuscated Files or Information (AI-style Syntax)   |

---

## Hunt Query Logic

This query detects:

- PowerShell processes containing numbered AI-generated comment markers  
- AI-centric script artifacts like progress indicators or verbose instructional comments  
- Structured natural language patterns like “Download and decode” + “Persistence set”  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM  

```xql
// Title: AdaptixC2 AI-Generated Script Indicators
// Description: Detects AI-authored PowerShell loaders based on synthetic markers such as numbered comments, verbose instructional text, or progress indicators.
// MITRE ATT&CK TTP ID: T1059.001

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = PROCESS and event_sub_type = ENUM.PROCESS_START  

| filter actor_process_image_name ~= "powershell.exe"  

| alter   
    detection_name = "AdaptixC2 AI-Generated Script Indicators",  
    attack_technique = "T1059.001 - PowerShell",  
    has_numbered_comments = if(actor_process_command_line contains "// [1"  
                            or actor_process_command_line contains "// [2"  
                            or actor_process_command_line contains "// [3", "yes", "no"),  
    has_progress_indicators = if(actor_process_command_line contains "[✔"  
                              or actor_process_command_line contains "[✓"  
                              or actor_process_command_line contains "[DONE", "yes", "no"),  
    has_verbose_comments = if(actor_process_command_line contains "# Download"  
                           or actor_process_command_line contains "# Execute"  
                           or actor_process_command_line contains "# Persistence"  
                           or actor_process_command_line contains "# Decode", "yes", "no")  

| alter   
    ai_pattern_flag = if((has_numbered_comments = "yes" and has_progress_indicators = "yes")  
                     or has_verbose_comments = "yes", "yes", "no") 

| filter ai_pattern_flag = "yes"  
   or (actor_process_command_line contains "Download and decode"  
       and actor_process_command_line contains "Persistence set")  

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, has_numbered_comments, has_progress_indicators, has_verbose_comments, ai_pattern_flag, detection_name, attack_technique  

| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Command-Line  |

---

## Execution Requirements

- **Required Permissions:** Ability to execute PowerShell scripts.  
- **Required Artifacts:** Process creation logs that capture command-line text.  

---

## Considerations

- AI-assistant style artifacts are highly unusual in **malware tradecraft**, making detection with low FP likelihood.  
- Validate script context, as **developer prototypes or red team simulations** could also generate similar syntax.  
- Cross-reference suspicious script signals with **endpoint telemetry and persistence artifacts**.  

---

## False Positives

False positives may occur if:  
- Developers run GPT/AI-generated PowerShell code for testing.  
- Red teams or training exercises incorporate AI comments or instructional syntax.  

---

## Recommended Response Actions

1. Review suspicious PowerShell command arguments flagged with AI indicators.  
2. Correlate findings with downloads, payloads, persistence activity.  
3. Apply tighter threat hunting filters on user context and machine role.  
4. If malicious:  
   - Quarantine the endpoint  
   - Block further PowerShell script execution  
   - Assess lateral movement attempts  

---

## References

- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1036.005 – Masquerading](https://attack.mitre.org/techniques/T1036/005/)  
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)  

---

## Version History

| Version | Date       | Impact           | Notes                                                                 |
|---------|------------|-----------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-26 | Initial Release  | Created hunt query to detect AI-generated PowerShell indicators linked to AdaptixC2 |
