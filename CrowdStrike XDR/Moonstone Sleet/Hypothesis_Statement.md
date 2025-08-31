# Hypothesis Statement: Moonstone Sleet Threat Actor Activity

## Purpose
Guides the direction and scope of the threat hunt by focusing on specific, testable assumptions about Moonstone Sleet’s tactics, techniques, and procedures (TTPs) as observed in recent threat intelligence.

## Hypothesis Statement

**Moonstone Sleet, a North Korean state-aligned threat actor, is actively targeting organizations in the software development, education, and defense sectors by leveraging a combination of social engineering, trojanized legitimate tools (such as PuTTY), malicious npm packages, and custom game executables (e.g., DeTankWar) to gain initial access, establish persistence, and deploy ransomware (FakePenny) and credential theft malware. These activities are likely to manifest as anomalous process executions, suspicious file creations, and network connections to known Moonstone Sleet infrastructure within the environment.**

## Rationale
- Based on recent threat intelligence from Microsoft, Moonstone Sleet employs a diverse set of TTPs, including:
  - Delivery of trojanized PuTTY and other legitimate tools via social media, email, and freelancing platforms.
  - Use of malicious npm packages distributed as technical assessments or freelance projects, often leveraging curl to download additional payloads.
  - Deployment of a fully functional malicious game (DeTankWar) to deliver custom loaders (YouieLoad, SplitLoader) and establish persistence.
  - Creation of fake companies and personas to facilitate social engineering and phishing campaigns.
  - Use of custom ransomware (FakePenny) and credential theft tools, with ransom notes mimicking prior campaigns (e.g., NotPetya).
- These activities are observable and testable through endpoint, process, file, and network telemetry.

## Testable Predictions
- Unusual process executions involving PuTTY, npm, or game binaries from non-standard directories.
- Creation of files with names and characteristics matching ransom notes or loader artifacts.
- Outbound network connections to known Moonstone Sleet C2 domains (e.g., detankwar[.]com, ccwaterfall[.]com).
- Registry or scheduled task modifications referencing SplitLoader, YouieLoad, or other custom payloads.
- Service creation events with names or paths linked to YouieLoad or other Moonstone Sleet malware.

## References
- [Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks (Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)

