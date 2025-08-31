# QueryForge 🔥
*Forging powerful queries for threat hunters and defenders.*  

## 📖 Overview  
**QueryForge** is a curated collection of **CrowdStrike XDR** and **Cortex XDR** hunting queries, organized into structured **hunt campaigns**. The goal is to help defenders **detect what default alerts miss** by turning raw telemetry into actionable investigations.  

Not every malicious activity raises an immediate alert. By leveraging the **campaign-driven methodology** below, QueryForge enables defenders to **form hypotheses, run investigative hunts, and detect adversaries proactively.**

---

## 🎯 Threat Hunting Campaign Methodology  
Every hunt campaign in QueryForge follows a structured, repeatable approach:

1. **Hypothesis Statement**  
   - A testable assumption about potential threats or malicious activity.  
   - Example: *“Attackers are leveraging PowerShell to establish persistence in our environment.”*

2. **Hunt Missions (with Analytics)**  
   - Actionable investigative tasks derived from the hypothesis.  
   - Each mission includes associated **queries and analytics** to validate or refute the assumption.  
   - Example missions for the above hypothesis:  
     - Identify unusual PowerShell executions  
     - Investigate suspicious registry persistence related to PowerShell  
     - Query XDR logs for encoded/obfuscated command-line arguments  

---

## 📂 Repository Structure  

```
/QueryForge
  ├── README.md
  ├── LICENSE
  ├── CrowdStrike-XDR/
  │    ├── LockBit-Ransomware/
  │    │    ├── Hypothesis.md
  │    │    └── Hunt-Missions.md
  │    ├── APT29/
  │    │    ├── Hypothesis.md
  │    │    └── Hunt-Missions.md
  │    └── ...
  ├── Cortex-XDR/
  │    ├── Emotet-Campaign/
  │    │    ├── Hypothesis.md
  │    │    └── Hunt-Missions.md
  │    ├── Log4Shell-Exploitation/
  │    │    ├── Hypothesis.md
  │    │    └── Hunt-Missions.md
  │    └── ...
```

### Structure Explanation
- **CrowdStrike-XDR/** and **Cortex-XDR/** – platform-specific folders.  
- **Threat Campaign folders** – titled after a **threat actor, ransomware, malware campaign, or vulnerability exploitation** (e.g., *APT29*, *LockBit-Ransomware*, *Log4Shell-Exploitation*).  
- **Inside each campaign**:  
  - `Hypothesis.md` → defines the focus of the hunt.  
  - `Hunt-Missions.md` → includes investigative tasks *and the supporting analytics/queries*.  

---

## 📢 Usage & Attribution  
- You are free to **use, adapt, and share** these queries in your own environment.  
- If you share or reuse this material, please credit the author:  
  - LinkedIn: [www.linkedin.com/in/4ale](https://www.linkedin.com/in/4ale)  
  - GitHub: [@ThreatHuntingOps/QueryForge](https://github.com/ThreatHuntingOps/QueryForge)  
- 🚫 **External contributions are not being accepted at this time.** This repository is maintained solely by its author to ensure content consistency and quality.  
- 🚫 Do not present this material as your own without attribution - it is forbidden.  

---

## 🔑 Key Takeaways  
- **QueryForge** = a living, open-source repository of XDR hunt campaigns.  
- Organized around **Hypothesis → Hunt Missions (with Analytics)** under campaign folders, titled after **real threats**.  
- Empowering defenders to detect and mitigate adversaries **before alerts fire**.  

---

⚡ Ready to hunt? Explore the campaign folders, run the queries in your **CrowdStrike XDR** or **Cortex XDR** environment, and forge your own hunts.  
