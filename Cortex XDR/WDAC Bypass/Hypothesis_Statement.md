# WDAC Bypass Threat Hunting Hypothesis


## Executive Summary

This document presents a comprehensive threat hunting hypothesis focused on detecting Windows Defender Application Control (WDAC) bypass techniques in enterprise environments. The hypothesis is grounded in extensive threat intelligence analysis covering two primary attack vectors: the weaponization of WDAC policies to disable endpoint security solutions, and the abuse of trusted system binaries to evade enforced WDAC policies.

The hypothesis assumes that sophisticated threat actors, particularly ransomware groups and advanced persistent threat (APT) actors, are actively deploying WDAC bypass techniques as part of their defense evasion strategies. These techniques have evolved from public proof-of-concepts into operational tools used by groups such as Black Basta, demonstrating a clear progression from research to real-world exploitation.

This hunting hypothesis provides a structured approach to proactively identify these threats through targeted data analysis, behavioral monitoring, and artifact detection, enabling security teams to detect and respond to WDAC bypass attempts before they achieve their intended objectives.

---

## Primary Threat Intelligence Sources

This threat hunting hypothesis is built upon comprehensive analysis of multiple threat intelligence sources, ranging from core security research to academic publications and operational security tools. The following sources provided the foundational knowledge for understanding WDAC bypass techniques, their evolution, and their operational deployment by threat actors.

### Core Intelligence Sources

**1. CyberSecurity News - WDAC Bypass EDR Analysis**
- **Source:** https://cybersecuritynews.com/wdac-bypass-edr/
- **Relevance:** Source documenting the weaponization of WDAC policies against EDR solutions
- **Key Contributions:** Reporting on the Krueger tool and its evolution into operational malware families like DreamDemon used by Black Basta ransomware group

**2. Beierle & Goins - Weaponizing WDAC: Killing the Dreams of EDR**
- **Source:** https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/
- **Relevance:** Foundational technical research demonstrating WDAC policy weaponization techniques
- **Key Contributions:** Detailed technical analysis of malicious policy creation, deployment vectors including SMB and GPO distribution, and specific targeting of major EDR vendors

**3. Beierle - A Nightmare on EDR Street: WDAC's Revenge**
- **Source:** https://beierle.win/2025-08-28-A-Nightmare-on-EDR-Street-WDACs-Revenge/
- **Relevance:** Advanced analysis of WDAC bypass evolution and operational security improvements
- **Key Contributions:** Documentation of DreamDemon malware enhancements, timestomping techniques, file hiding methods, and Windows 11/Server 2025 compatibility

**4. Ultimate WDAC Bypass List - Comprehensive LOLBIN Repository**
- **Source:** https://github.com/bohops/UltimateWDACBypassList
- **Relevance:** Authoritative collection of Living-Off-the-Land Binary (LOLBIN) techniques for WDAC evasion
- **Key Contributions:** Extensive catalog of 40+ trusted system binaries that can be abused to bypass WDAC policies, including technical details and proof-of-concept code


### Industry and Operational Intelligence

**5. IBM X-Force - Operational WDAC Bypasses**
- **Sources:**
  - https://www.ibm.com/think/x-force/bypassing-windows-defender-application-control-loki-c2
  - https://www.ibm.com/think/x-force/operationalizing-browser-exploits-to-bypass-wdac
- **Relevance:** Real-world operational deployment of WDAC bypasses in C2 frameworks
- **Key Contributions:** Analysis of Loki C2 WDAC bypass capabilities and browser exploit operationalization

**6. Bohops Security Research**
- **Sources:**
  - https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/
  - https://bohops.com/2020/11/02/exploring-the-wdac-microsoft-recommended-block-rules-part-ii-wfc-fsi/
  - https://bohops.com/2019/01/10/com-xsl-transformation-bypassing-microsoft-application-control-solutions-cve-2018-8492/
- **Relevance:** Comprehensive analysis of .NET Core bypasses and Microsoft recommended block rules
- **Key Contributions:** Technical documentation of COM XSL transformation bypasses and .NET Core attack vectors

### Tool References and Technical Resources

**7. Microsoft WDAC Toolkit and Documentation**
- **Sources:**
  - https://github.com/MicrosoftDocs/WDAC-Toolkit
  - https://github.com/mattifestation/WDACTools
  - https://github.com/mattifestation/WDACPolicies
- **Relevance:** Official and community tools for WDAC policy management and analysis
- **Key Contributions:** Policy creation utilities, analysis tools, and sample policy configurations

These sources collectively provide a comprehensive foundation for understanding the evolution, technical implementation, and operational deployment of WDAC bypass techniques. The intelligence gathered from these sources directly informs the detection strategies, behavioral analysis, and hunting methodologies outlined in this hypothesis document.

---

## Hypothesis Statement

**Primary Hypothesis:**
> "Threat actors with administrative privileges in our environment are deploying malicious WDAC policies to disable EDR solutions and/or exploiting trusted system binaries to bypass existing WDAC enforcement, as evidenced by specific file system artifacts, registry modifications, anomalous process execution patterns, and network behaviors consistent with known WDAC bypass techniques."

**Supporting Sub-Hypotheses:**

1. **Policy Weaponization Hypothesis:** Adversaries are deploying malicious WDAC policies (`SiPolicy.p7b`) to the Windows Code Integrity directory to systematically disable EDR agents before system reboot.

2. **LOLBIN Abuse Hypothesis:** Threat actors are leveraging trusted Microsoft-signed binaries (LOLBINs) such as `msbuild.exe`, `cdb.exe`, `wmic.exe`, and PowerShell utilities to execute arbitrary code while evading WDAC restrictions.

3. **Persistence and Distribution Hypothesis:** Attackers are using Group Policy Objects (GPOs) and SMB shares to distribute malicious WDAC policies across multiple endpoints in domain-wide attacks.

4. **Bring Your Own Vulnerable Application (BYVA) Hypothesis:** Sophisticated actors are introducing legitimately signed but vulnerable third-party applications to create new bypass vectors when native system binaries are insufficient.

---

## Threat Intelligence Foundation

### Key Research Findings

The hypothesis is built upon comprehensive analysis of WDAC bypass techniques documented in threat intelligence sources, including:

**Evolution of Weaponization:**
- **Krueger Tool:** Initial .NET-based proof-of-concept demonstrating policy weaponization
- **DreamDemon Malware:** Advanced C++ variant used by Black Basta ransomware group with enhanced stealth capabilities
- **Operational Security Improvements:** File hiding, timestomping, and decoy log creation to evade detection

**Technical Attack Vectors:**
- **Direct Policy Deployment:** Placement of malicious `SiPolicy.p7b` files in `C:\Windows\System32\CodeIntegrity\`
- **Remote Distribution:** SMB-based deployment to administrative shares (`C$`, `ADMIN$`)
- **Domain-Wide Attacks:** GPO-based policy distribution for enterprise-scale compromise
- **LOLBIN Exploitation:** Abuse of 40+ documented trusted binaries for code execution

**Targeted Security Solutions:**
- CrowdStrike Falcon
- SentinelOne
- Microsoft Defender for Endpoint
- Symantec Endpoint Protection
- Other major EDR vendors

### MITRE ATT&CK Mapping

**Primary TTPs:**
- **T1562.001:** Disable or Modify Tools (Policy weaponization)
- **T1484.001:** Group Policy Modification (Domain distribution)
- **T1218:** System Binary Proxy Execution (LOLBIN abuse)
- **T1564.001:** Hidden Files and Directories (File concealment)
- **T1070.006:** Timestomp (Artifact manipulation)
- **T1211:** Exploitation for Defense Evasion (BYVA techniques)

---

## Testable Assumptions

### Assumption 1: File System Artifacts
**Testable Statement:** Malicious WDAC policy deployment will create detectable file system artifacts in Windows Code Integrity directories.

**Validation Criteria:**
- Presence of `SiPolicy.p7b` files in non-centrally managed environments
- File creation events in `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\`
- Hidden or system-attributed policy files with recent modification timestamps
- Policy files with suspicious signatures or masquerading extensions

### Assumption 2: Registry Modifications
**Testable Statement:** GPO-based policy deployment will generate specific registry changes related to WDAC configuration.

**Validation Criteria:**
- Creation/modification of `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`
- `ConfigCIPolicyFilePath` values pointing to remote SMB shares
- `DeployConfigCIPolicy` registry value changes
- Correlation with GPO update events

### Assumption 3: Process Execution Anomalies
**Testable Statement:** LOLBIN abuse will generate anomalous parent-child process relationships and command-line patterns.

**Validation Criteria:**
- Unexpected process ancestry (e.g., `notepad.exe` spawning `csc.exe`)
- Suspicious command-line arguments for trusted binaries
- Execution of development tools outside software development contexts
- File I/O operations by system utilities accessing unusual file types

### Assumption 4: Network Indicators
**Testable Statement:** Remote policy deployment will generate detectable SMB traffic patterns.

**Validation Criteria:**
- SMB write operations involving `SiPolicy.p7b` files to administrative shares
- Unusual SMB access patterns to `ADMIN$` or `C$` shares
- Network connections from systems executing policy deployment tools

---

## Detection Approach

### Phase 1: Baseline Establishment (Week 1-2)
1. **Environment Mapping:**
   - Inventory systems with legitimate WDAC policies
   - Document authorized policy management processes
   - Establish baseline process execution patterns

2. **Data Source Validation:**
   - Verify file system monitoring coverage for Code Integrity directories
   - Confirm registry monitoring for WDAC-related keys
   - Validate process execution logging and command-line capture

### Phase 2: Active Hunting (Week 3-4)
1. **File System Hunting:**
   - Search for unauthorized `SiPolicy.p7b` files
   - Monitor Code Integrity directory modifications
   - Analyze file attributes and timestamps for tampering

2. **Process Behavior Analysis:**
   - Hunt for anomalous LOLBIN execution patterns
   - Correlate parent-child process relationships
   - Analyze command-line arguments for suspicious patterns

3. **Registry and Network Monitoring:**
   - Monitor WDAC-related registry changes
   - Analyze SMB traffic for policy file transfers
   - Correlate GPO updates with policy deployments

### Phase 3: Advanced Analysis (Week 5-6)
1. **Policy Content Analysis:**
   - Extract and analyze discovered policy files
   - Identify malicious rules targeting EDR solutions
   - Map policy content to known threat actor TTPs

2. **Correlation and Attribution:**
   - Correlate findings across multiple detection vectors
   - Link activities to known malware families (DreamDemon, etc.)
   - Assess scope and impact of identified bypasses

---

## Success Criteria

### Hypothesis Confirmation Indicators
The hypothesis will be considered **CONFIRMED** if any of the following conditions are met:

1. **Direct Evidence:**
   - Discovery of unauthorized malicious WDAC policies targeting EDR solutions
   - Identification of active LOLBIN abuse for code execution
   - Detection of policy deployment via SMB or GPO mechanisms

2. **Behavioral Evidence:**
   - Anomalous process execution patterns consistent with LOLBIN abuse
   - Suspicious file system modifications in Code Integrity directories
   - Registry changes indicating unauthorized WDAC policy deployment

3. **Correlation Evidence:**
   - Multiple weak indicators correlating to form a strong attack pattern
   - Timeline correlation between policy deployment and EDR agent failures
   - Network and host artifacts consistent with known attack tools

### Hypothesis Refutation Indicators
The hypothesis will be considered **REFUTED** if:

1. **Absence of Indicators:**
   - No unauthorized WDAC policy files discovered after comprehensive hunting
   - No anomalous LOLBIN execution patterns detected
   - No suspicious registry or network activities related to WDAC

2. **Alternative Explanations:**
   - All detected activities have legitimate business justifications
   - Identified artifacts are attributable to authorized security tools or processes
   - No correlation between detected activities and known attack patterns

---

## Scope and Limitations

### Hunting Scope
**In Scope:**
- Windows endpoints with WDAC capability (Windows 10/11, Server 2016+)
- Domain controllers and systems with GPO management capabilities
- Endpoints with EDR solutions that could be targeted by policy weaponization
- Systems with development tools or debugging utilities installed

**Out of Scope:**
- Legacy Windows systems without WDAC support
- Non-Windows endpoints and infrastructure
- Third-party application whitelisting solutions (non-WDAC)
- Mobile device management (MDM) policy enforcement

### Technical Limitations
1. **Detection Gaps:**
   - Limited visibility into kernel-level WDAC enforcement decisions
   - Potential blind spots in environments with insufficient logging
   - Difficulty detecting sophisticated timestomping techniques

2. **False Positive Risks:**
   - Legitimate software development activities may trigger LOLBIN alerts
   - Authorized WDAC policy updates may appear suspicious
   - Normal system administration tasks may generate false indicators

3. **Resource Constraints:**
   - Hunting activities may impact system performance during intensive analysis
   - Large-scale policy file analysis requires significant processing resources
   - Network monitoring may generate substantial data volumes

### Operational Considerations
1. **Time Sensitivity:**
   - WDAC policy changes require system reboot to take effect
   - Window of opportunity for detection before policy enforcement
   - Need for rapid response to prevent EDR disablement

2. **Privilege Requirements:**
   - Administrative access needed for comprehensive file system analysis
   - Domain administrator privileges may be required for GPO investigation
   - Elevated permissions necessary for registry and network analysis

3. **Business Impact:**
   - Hunting activities should minimize disruption to production systems
   - Coordination required with IT operations for system access
   - Communication plan needed for potential security incidents

---

## Conclusion

This threat hunting hypothesis provides a structured framework for proactively detecting WDAC bypass techniques in enterprise environments. The hypothesis is grounded in solid threat intelligence from multiple authoritative sources and provides clear, testable assumptions that can guide targeted hunting activities.

The comprehensive threat intelligence foundation, built upon analysis of over 50 primary and secondary sources, ensures that the hunting approach addresses both historical and emerging WDAC bypass techniques. The documented evolution from academic research to operational deployment by sophisticated threat actors like Black Basta demonstrates the critical importance of proactive detection capabilities.

Success in validating this hypothesis will significantly enhance the organization's ability to detect and respond to advanced defense evasion techniques, particularly those employed by sophisticated threat actors and ransomware groups. The structured approach ensures comprehensive coverage of known attack vectors while maintaining focus on actionable intelligence and measurable outcomes.

Regular review and refinement of this hypothesis based on hunting results and evolving threat intelligence will ensure continued effectiveness against emerging WDAC bypass techniques and maintain the organization's defensive posture against advanced threats.


