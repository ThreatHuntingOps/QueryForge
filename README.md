<p align="center">
  <img src="assets/QF Banner.png" alt="QueryForge Banner" width="100%"/>
</p>

# QueryForge 🔥  
*Forging powerful detection engineering content for threat hunters and defenders.*  

---

📖 **Overview**  
QueryForge is a curated collection of **threat hunting queries, analytics, and correlation rules** for platforms such as **CrowdStrike Falcon XDR**, **Palo Alto Cortex XDR**, and **Palo Alto XSIAM**.  

The repository helps defenders go **beyond out‑of‑the‑box detections** by:  
- Developing **hypothesis-driven hunts**,  
- Running targeted investigations,  
- Engineering **advanced correlation rules** for proactive detection,  
- Continuously adapting content against **real-world adversaries**.  

---

🎯 **Threat Hunting & Detection Engineering Approach**  
Each campaign follows a structured methodology:  

1. **Hypothesis** – a testable assumption about adversary techniques.  
2. **Hunt Missions & Queries** – analytic-driven searches across endpoint/XDR datasets.  
3. **Detection Engineering** – translation into **correlated detection content**.  
4. **Validation & Iteration** – refining coverage against evolving adversary tradecraft.  

---

📂 **Repository Highlights**  
```
/QueryForge
  ├─ CrowdStrike XDR/
  │     ├─ Remote Monitoring & Management (RMM) Tools/
  │     │     └─ RMM_Tools_Threat_Hunt.md
  │     └─ PipeMagic-Backdoor/
  ├─ Cortex XDR/
  │     ├─ Silver-Fox-APT/
  │     ├─ SharePoint-0day/
  │     ├─ The-DFIR-Report-Multi-Ransomware/
  │     └─ WDAC-Bypass/
         │    ├─ Hunt-Queries.md
         │    ├─ CorrelationRule1_WDAC_EDR_Impairment.md
         │    └─ CorrelationRule2_*.md
```

---

🌟 **Featured Campaigns**  

- **WDAC Bypass** – Detection of **EDR impairment & WDAC bypass techniques**. Includes hunts + correlation rules.  
- **Silver Fox APT** – Hunt content aligned to APT tradecraft (persistence, escalation).  
- **SharePoint 0‑Day** – Queries for exploitation of vulnerable SharePoint servers.  
- **The DFIR Report – Multi‑Ransomware** – Mapping DFIR‑documented ransomware intrusions into hunts & detections.  
- **RMM Tools Threat Hunt** – Detects misuse of **legitimate RMM tools** by adversaries.  
- **PipeMagic Backdoor** – Persistence + backdoor activity abusing named pipes.  

---

📊 **Campaign Overview with MITRE ATT&CK Mappings**  

| Platform               | Campaign                           | Focus Area                                                | Content Type                          | ATT&CK Mapping (Examples)                  |
|------------------------|------------------------------------|----------------------------------------------------------|---------------------------------------|--------------------------------------------|
| **Cortex XDR / XSIAM** | WDAC Bypass                        | Detection of **EDR impairment & WDAC bypass techniques** | Hunt queries + correlation rules       | **Defense Evasion** (T1562.001, T1562.006) |
| **Cortex XDR / XSIAM** | Silver Fox APT                     | **APT campaign tradecraft**: persistence & escalation    | Hypotheses + hunt queries              | **Persistence** (T1547), **Privilege Esc.** (T1068) |
| **Cortex XDR / XSIAM** | SharePoint 0‑Day                   | **Exploitation of SharePoint servers**                   | Hunt queries + detection logic         | **Initial Access** (T1190), **Execution** (T1203) |
| **Cortex XDR / XSIAM** | The DFIR Report – Multi-Ransomware | **Multi‑ransomware intrusion detection**                 | Hunt queries + hypotheses              | **Impact** (T1486), **Command & Control** (T1071) |
| **CrowdStrike XDR**    | RMM Tools Threat Hunt              | Abuse of **legitimate RMM tools** for persistence/remote | Hunt queries                           | **Execution** (T1569.002), **Persistence** (T1136) |
| **CrowdStrike XDR**    | PipeMagic Backdoor                 | **Persistence & backdoor** via named pipes               | Hunt queries + detection logic         | **Execution** (T1059), **Persistence** (T1547.013) |


---

📢 **Usage & Attribution**  
- Free to use and adapt.  
- Attribution appreciated:  
  - GitHub: [@ThreatHuntingOps](https://github.com/ThreatHuntingOps/QueryForge)  
  - LinkedIn: [4ale](https://www.linkedin.com/in/4ale)  

---

🔑 **Key Takeaways**  
- **QueryForge** = hypothesis-driven hunts + advanced correlation engineering.  
- Organized by **real campaigns & adversary TTPs**.  
- MITRE ATT&CK mapped.
---

⚡ **Ready to Hunt?**  
Explore the campaigns, run the hunts in your **Cortex XDR, XSIAM, or CrowdStrike Falcon**, and transform them into **high‑fidelity detections**.  
