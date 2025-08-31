# Windows LOLBins Hunt Query Documentation

## Overview
This hunt query detects suspicious or unexpected execution of Windows Living Off The Land Binaries (LOLBins) by comparing process execution events against a curated list of known LOLBins (`win_lolbins.csv`). It highlights cases where the executing file's path or name does not match the expected values, which may indicate masquerading or abuse by threat actors.

---

## Hunt Query Logic

- Retrieves all Windows process execution events.
- Matches process `FileName` against the LOLBins list in `win_lolbins.csv`.
- Normalizes file paths and names to create a unique key for each execution.
- Flags executions where the file's path or name does not match the expected LOLBin key.
- Outputs relevant process and file details, including links to CrowdStrike Process Explorer and the LOLBAS project.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Hunt Living Off The Land Binaries 
// Get all process executions for Windows systems 

#event_simpleName=ProcessRollup2 event_platform="Win" 

// Check to make sure FileName is on our LOLBINS list located in lookup file 
| match(file="win_lolbins.csv", field="FileName", column=FileName, include=[FileName, Description, Paths, URL], strict=true) 

// Massage ImageFileName so a true key pair value can be created that combines file path and file name 
| regex("(\\Device\\HarddiskVolume\d+)?(?<ShortFN>.+)", field=ImageFileName, strict=false) 
| ShortFN:=lower("ShortFN") 
| FileNameLower:=lower("FileName") 
| RunningKey:=format(format="%s_%s", field=[FileNameLower, ShortFN]) 

// Check to see where the executing file's key doesn't match an expected key value for an LOLBIN 
| !match(file="win_lolbins.csv", field="RunningKey", column=key, strict=true) 

// Output results to table 
| table([aid, ComputerName, UserName, ParentProcessId, ParentBaseFileName, FileName, ShortFN, Paths, CommandLine, Description, Paths, URL]) 

// Clean up "Paths" to make it easier to read 
| Paths =~replace(", ", with="
") 

// Rename two fields so they are more explicit 
| rename([[ShortFN, ExecutingFilePath], [Paths, ExpectFilePath]]) 

// Add Link for Process Explorer 
| rootURL := "https://falcon.crowdstrike.com/" /* US-1 */ 
//| rootURL  := "https://falcon.us-2.crowdstrike.com/" /* US-2 */ 
//| rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" /* Gov */ 
//| rootURL  := "https://falcon.eu-1.crowdstrike.com/"  /* EU */ 
| format("[PrEx](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "ParentProcessId"], as="ProcessExplorer") 

// Add link back to LOLBAS Project 
| format("[LOLBAS](%s)", field=[URL], as="Link") 

// Remove unneeded fields 
| drop([rootURL, ParentProcessId, URL])
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Falcon       | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements
- **Required Permissions:** Ability to collect process execution events from Windows endpoints.
- **Required Artifacts:** LOLBins reference file (`win_lolbins.csv`), process execution logs.

---

## Considerations
- Investigate any LOLBin execution where the file path or name does not match the expected value.
- Review the parent process and command line for additional context.
- Validate the legitimacy of the binary and its source.

---

## False Positives
False positives may occur if:
- Legitimate binaries are relocated or renamed as part of IT operations.
- Custom deployments use alternate paths for system binaries.

---

## Recommended Response Actions
1. Investigate the context of the suspicious LOLBin execution.
2. Validate the binary's signature and source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Cool Query Friday](https://www.reddit.com/r/crowdstrike/comments/1dal47a/20240607_cool_query_friday_custom_lookup_files_in/)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect suspicious LOLBin execution and potential masquerading         |
