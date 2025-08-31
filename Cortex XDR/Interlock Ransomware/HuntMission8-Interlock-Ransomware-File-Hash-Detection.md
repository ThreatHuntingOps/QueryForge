# Detection of Interlock-Associated Files by SHA-256 Hash

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Interlock-File-Hash-Detection
- **Operating Systems:** WindowsEndpoint, WindowsServer, Linux
- **False Positive Rate:** Medium (some hashes may be legitimate tools)

---

## Hunt Analytics

This hunt detects the presence or execution of files (by SHA-256 hash) associated with Interlock ransomware activity, as identified in recent FBI investigations. These files include scripts, executables, DLLs, and archives used for initial access, lateral movement, credential theft, exfiltration, and impact. Some hashes may correspond to legitimate tools, so all results should be vetted before action. Detected behaviors include:

- Presence or execution of files matching known Interlock ransomware-related SHA-256 hashes
- Coverage for a wide range of attack stages: initial access, lateral movement, credential theft, exfiltration, and impact

These techniques are associated with Interlock ransomware campaigns and related threat actor activity.

---

## ATT&CK Mapping

| Tactic      | Technique | Subtechnique | Technique Name |
|-------------|-----------|--------------|---------------|
| Multiple    | Multiple  | —            | See previous queries for mapping to Execution, Persistence, Credential Access, Lateral Movement, Exfiltration, and Impact |

---

## Hunt Query Logic

This query identifies suspicious file events by looking for:

- Presence or execution of files with SHA-256 hashes associated with Interlock ransomware activity (as reported by the FBI in June 2025)

These patterns are indicative of known malware or tool usage by Interlock ransomware operators.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Interlock-Associated Files by SHA-256 Hash
// Description: Detects presence or execution of files (by SHA-256 hash) associated with Interlock ransomware actors, as reported by FBI in June 2025. Some hashes may be legitimate; vet before action.
// MITRE ATT&CK TTP ID: Multiple (see below)

config case_sensitive = false
| dataset = xdr_data
| filter action_file_sha256 in (
    "fba4883bf4f73aa48a957d894051d78e0085ecc3170b1ff50e61ccec6aeee2cd", "4b036cc9930bb42454172f888b8fde1087797fc0c9d31ab546748bd2496bd3e5", "18a507bf1c533aad8e6f2a2b023fbbcac02a477e8f05b095ee29b52b90d47421", "1a70f4eef11fbecb721b9bab1c9ff43a8c4cd7b2cafef08c033c77070c6fe069", "a4069aa29628e64ea63b4fb3e29d16dcc368c5add304358a47097eedafbbb565", "d535bdc9970a3c6f7ebf0b229c695082a73eaeaf35a63cd8a0e7e6e3ceb22795", "FAFCD5404A992850FFCFFEE46221F9B2FF716006AECB637B80E5CD5AA112D79C", "C20BABA26EBB596DE14B403B9F78DDC3C13CE9870EEA332476AC2C1DD582AA07", "1845a910dcde8c6e45ad2e0c48439e5ab8bbbeb731f2af11a1b7bbab3bfe0127", "44887125aa2df864226421ee694d51e5535d8c6f70e327e9bcb366e43fd892c1", "a70af759e38219ca3a7f7645f3e103b13c9fb1db6d13b68f3d468b7987540ddf", "96babe53d6569ee3b4d8fc09c2a6557e49ebc2ed1b965abda0f7f51378557eb1", "d0c1662ce239e4d288048c0e3324ec52962f6ddda77da0cb7af9c1d9c2f1e2eb", "A4F0B68052E8DA9A80B70407A92400C6A5DEF19717E0240AC608612476E1137E", "68A49D5A097E3850F3BB572BAF2B75A8E158DADB70BADDC205C2628A9B660E7A", "88f26f3721076f74996f8518469d98bf9be0eaee5b9eccc72867ebfc25ea4e83", "078163d5c16f64caa5a14784323fd51451b8c831c73396b967b4e35e6879937b", "7a43789216ce242524e321d2222fa50820a532e29175e0a2e685459a19e09069", "97931d2e2e449ac3691eb526f6f60e2f828de89074bdac07bd7dbdfd51af9fa0", "ff7ad2376ae01e4b3f1e1d7ae630f87b8262b5c11bc5d953e1ac34ffe81401b5", "64a0ab00d90682b1807c5d7da1a4ae67cde4c5757fc7d995d8f126f0ec8ae983", "2814b33ce81d2d2e528bb1ed4290d665569f112c9be54e65abca50c41314d462", "f51b3d054995803d04a754ea3ff7d31823fab654393e8054b227092580be43db", "dfb5ba578b81f05593c047f2c822eeb03785aecffb1504dcb7f8357e898b5024", "94bf0aba5f9f32b9c35e8dfc70afd8a35621ed6ef084453dc1b10719ae72f8e2", "28c3c50d115d2b8ffc7ba0a8de9572fbe307907aaae3a486aabd8c0266e9426f", "70bb799557da5ac4f18093decc60c96c13359e30f246683815a512d7f9824c8f", "73a9a1e38ff40908bcc15df2954246883dadfb991f3c74f6c514b4cffdabde66", "1d04e33009bcd017898b9e1387e40b5c04279c02ebc110f12e4a724ccdb9e4fb", "7b9e12e3561285181634ab32015eb653ab5e5cfa157dd16cdd327104b258c332", "70EE22D394E107FBB807D86D187C216AD66B8537EDC67931559A8AEF18F6B5B3", "8eb7e3e8f3ee31d382359a8a232c984bdaa130584cad11683749026e5df1fdc3", "e4d6fe517cdf3790dfa51c62457f5acd8cb961ab1f083de37b15fd2fddeb9b8f", "e86bb8361c436be94b0901e5b39db9b6666134f23cce1e5581421c2981405cb1", "c733d85f445004c9d6918f7c09a1e0d38a8f3b37ad825cd544b865dba36a1ba6"
)
| fields _time, agent_hostname, agent_os_type, actor_effective_username, action_file_name, action_file_path, action_file_sha256, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | File, Process      | File Creation/Modification, Process Creation |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to create, modify, or execute files.
- **Required Artifacts:** File creation/modification logs, process creation logs, and SHA-256 hash values.

---

## Considerations

- Review the file hash, name, and context for legitimacy.
- Correlate with user activity, threat intelligence, and system logs to determine if the file is malicious or a false positive.
- Investigate any execution or presence of files matching these hashes for signs of compromise.

---

## False Positives

False positives may occur if:

- Legitimate tools or files share a hash with those reported in threat intelligence.
- Security tools or IT staff use files with matching hashes for benign purposes.

---

## Recommended Response Actions

1. Investigate the file hash, name, and context for intent and legitimacy.
2. Analyze the file for malicious content and compare with threat intelligence.
3. Review user activity and system logs for signs of compromise or lateral movement.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor files matching known Interlock ransomware hashes.

---

## References

- [Unit 42: Interlock Ransomware Analysis](https://unit42.paloaltonetworks.com/interlock-ransomware/)
- [MITRE ATT&CK: Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-23 | Initial Detection | Created hunt query to detect Interlock-associated files by SHA-256 hash                     |
