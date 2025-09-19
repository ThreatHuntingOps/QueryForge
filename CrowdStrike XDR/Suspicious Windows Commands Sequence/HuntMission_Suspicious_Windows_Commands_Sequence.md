# Suspicious Windows Commands Sequence

## Severity or Impact of the Detected Behavior
- **Risk Score:** `75`
- **Severity:** `High`

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-SuspiciousWinCommands
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects potentially suspicious sequences of Windows commands that may indicate malicious activity.  
It focuses on the execution of **Living Off The Land Binaries and Scripts (LOLBins)** and other trusted system utilities that are often abused by adversaries.

Detected suspicious behaviors include:
- Use of administrative and network utilities (`net.exe`, `sc.exe`, `wmic.exe`)
- Attempts to manage services, create accounts, and modify system configurations
- Execution of tools commonly associated with lateral movement and system discovery

Such sequences often indicate **post-exploitation attacker activity**, such as **privilege escalation, credential theft, defense evasion, or persistence**.

---

## ATT&amp;CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                         |
|-------------------------------|--------------|--------------|--------------------------------------------------------|
| TA0002 - Execution            | T1059        | 003          | Command and Scripting Interpreter: Windows Command     |
| TA0007 - Discovery            | T1082        | —            | System Information Discovery                          |
| TA0006 - Credential Access    | T1552        | —            | Unsecured Credentials                                 |
| TA0003 - Persistence          | T1053        | 005          | Scheduled Task/Job: Scheduled Task                    |
| TA0008 - Lateral Movement     | T1021        | 002          | Remote Services: SMB/Windows Admin Shares             |
| TA0005 - Defense Evasion      | T1036        | 005          | Masquerading: Match Legitimate Name or Location       |

---

## Hunt Query Logic

This query identifies suspicious command-line executions by:
- Monitoring `ProcessRollup2` events from Windows systems
- Identifying parent processes such as `cmd.exe` or `explorer.exe`
- Assigning behavior weights to critical LOLBins and system utilities
- Scoring events based on **command type** and **parameters**
- Raising alerts when thresholds are met (more than 5 LOLBins and cumulative weighted activity)

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon  

```fql
//  Suspicious Windows Commands Sequence
#repo="base_sensor" #event_simpleName="ProcessRollup2" event_platform="Win"
| in(GrandParentBaseFileName, values=["explorer.exe", "cmd.exe"])
// Add exclusions here 
| NOT (
    CommandLine=/^\/k\ echo\ \{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}$/i OR
    CommandLine=/"C:\\Program\ Files\ \(x86\)\\BigFix\ Enterprise\\BES\ Installers\\BFI_installer\\BFI\ v11\.0\.1\.0\ Installer\\tools\\getId\.vbs"/i OR
    CommandLine=/\\windows\\system32\\conhost\.exe\ 0x[a-f0-9]+\ \-forcev1/i
)
| ProcessStartTime := ProcessStartTime*1000
| execTime := formatTime("%Y-%m-%d %H", field=ProcessStartTime, locale=en_US, timezone=Z)
| FileName := lower(FileName)
| regex("(sc|net1?)\s+(?<cmdParam>\S+)\s+", field=CommandLine, strict=false)
| cmdParam := lower(cmdParam)
// Add checks commandline parameters here for better accuracy
// As the weights are different for different params of the same command, this might lead to overlaps. Ensure that cases with bigger weights of the same command are defined first, to be evaluated with priority. 
| case {
    FileName=/net1?\.exe/ cmdParam="stop" CommandLine=/falcon/i | behaviorWeight := "25" ;
    FileName=/net1?\.exe/ cmdParam=/(user|localgroup)/ CommandLine=/(\/delete|\/add)/ | behaviorWeight := "10" ;
    FileName=/net1?\.exe/ cmdParam="group" CommandLine=/\/domain\s+/i | behaviorWeight := "5" ;
    FileName=/net1?\.exe/ cmdParam="group" CommandLine=/admin/i | behaviorWeight := "5" ;
    FileName=/net1?\.exe/ cmdParam=/(start|stop)/ | behaviorWeight := "4" ;
    FileName=/net1?\.exe/ cmdParam="share" | behaviorWeight := "2" ;

    FileName="sc.exe" cmdParam=/(query|stop)/i CommandLine=/csagent/i | behaviorWeight := "25" ;
    FileName="sc.exe" cmdParam=/(start|stop)/ | behaviorWeight := "4" ;

    FileName="nltest.exe" | behaviorWeight := "3" ;
    FileName="systeminfo.exe" | behaviorWeight := "3" ;
    FileName="whoami.exe" | behaviorWeight := "3" ;
    FileName="ping.exe" | behaviorWeight := "3" ;
    FileName="hostname.exe" | behaviorWeight := "3" ;
    FileName="ipconfig.exe" | behaviorWeight := "3" ;
    FileName="xcopy.exe" | behaviorWeight := "3" ;
    FileName="reg.exe" | behaviorWeight := "3";
    FileName="arp.exe" | behaviorWeight := "3" ;
    FileName="bitsadmin.exe" | behaviorWeight := "5" ;
    FileName="csvde.exe" | behaviorWeight := "4" ;
    FileName="dsquery.exe" | behaviorWeight := "4" ;
    FileName="ftp.exe" | behaviorWeight := "5" ;
    FileName="makecab.exe" | behaviorWeight := "3" ;
    FileName="nbtstat.exe" | behaviorWeight := "3" ;
    FileName="netsh.exe" | behaviorWeight := "4" ;
    FileName="netstat.exe" | behaviorWeight := "3" ;
    FileName="nslookup.exe" | behaviorWeight := "3" ;
    FileName="quser.exe" | behaviorWeight := "3" ;
    FileName="regsvr32.exe" | behaviorWeight := "5" ;
    FileName="rundll32.exe" | behaviorWeight := "4" ;
    FileName="route.exe" | behaviorWeight := "3" ;
    FileName="schtasks.exe" | behaviorWeight := "4" ;
    FileName="taskkill.exe" | behaviorWeight := "3" ;
    FileName="tasklist.exe" | behaviorWeight := "3" ;
    FileName="wevtutil.exe" | behaviorWeight := "4" ;
    FileName="xcopy.exe" | behaviorWeight := "3" ;
    FileName="wmic.exe" | behaviorWeight := "6" ;
    FileName="vssadmin.exe" | behaviorWeight := "6" ;
    FileName="psexec.exe" | behaviorWeight := "8" ;
    FileName="psexesvc.exe" | behaviorWeight := "8" ;
    FileName="utilman.exe" | behaviorWeight := "5" ;
    FileName="msiexec.exe" | behaviorWeight := "4" ;
    FileName="mshta.exe" | behaviorWeight := "5" ;
    FileName="wscript.exe" | behaviorWeight := "5" ;
    FileName="cscript.exe" | behaviorWeight := "5" ;
    FileName="csc.exe" | behaviorWeight := "4" ;
    FileName="mmc.exe" | behaviorWeight := "3" ;
    FileName="control.exe" | behaviorWeight := "3" ;
    FileName="installutil.exe" | behaviorWeight := "5" ;
    FileName="msbuild.exe" | behaviorWeight := "5" ;
    FileName="cmdkey.exe" | behaviorWeight := "4" ;
    FileName="cmstp.exe" | behaviorWeight := "5" ;
    FileName="certutil.exe" | behaviorWeight := "5" ;
    FileName="regasm.exe" | behaviorWeight := "5" ;
    FileName="regsvcs.exe" | behaviorWeight := "5" ;
    FileName="rpcping.exe" | behaviorWeight := "4" ;
    FileName="remote.exe" | behaviorWeight := "4" ;
    FileName="dfsvc.exe" | behaviorWeight := "4" ;
    FileName="diskshadow.exe" | behaviorWeight := "4" ;
    FileName="bash.exe" | behaviorWeight := "5" ;
    FileName="esentutl.exe" | behaviorWeight := "4" ;
    FileName="msxsl.exe" | behaviorWeight := "5" ;
    FileName="expand.exe" | behaviorWeight := "3" ;
    FileName="leexec.exe" | behaviorWeight := "5" ;
    FileName="hh.exe" | behaviorWeight := "4" ;
    FileName="forfiles.exe" | behaviorWeight := "4" ;
    FileName="infdefaultinstall.exe" | behaviorWeight := "5" ;
    FileName="ie4unit.exe" | behaviorWeight := "4" ;
    FileName="msdt.exe" | behaviorWeight := "5" ;
    FileName="mavinject.exe" | behaviorWeight := "5" ;
    FileName="findstr.exe" | behaviorWeight := "3" ;
    FileName="odbcconf.exe" | behaviorWeight := "4" ;
    FileName="pcalua.exe" | behaviorWeight := "4" ;
    FileName="regedit.exe" | behaviorWeight := "5" ;
    FileName="qprocess.exe" | behaviorWeight := "3" ;
    FileName="print.exe" | behaviorWeight := "3" ;
    FileName="presentationhost.exe" | behaviorWeight := "4" ;
    FileName="xwizard.exe" | behaviorWeight := "4" ;
    FileName="syncappvpublishingserver.exe" | behaviorWeight := "4" ;
    FileName="scriptrunner.exe" | behaviorWeight := "5" ;
    FileName="runscripthelper.exe" | behaviorWeight := "5" ;
    FileName="robocopy.exe" | behaviorWeight := "3" ;
    FileName="replace.exe" | behaviorWeight := "3" ;
    FileName="regini.exe" | behaviorWeight := "4" ;
    FileName="extrac32.exe" | behaviorWeight := "4" ;
    FileName="csi.exe" | behaviorWeight := "4" ;
    FileName="cdb.exe" | behaviorWeight := "4" ;
    FileName="bginfo.exe" | behaviorWeight := "3" ;
    FileName="nvudisp.exe" | behaviorWeight := "3" ;
    FileName="nvuhda6.exe" | behaviorWeight := "3" ;
    FileName="tracker.exe" | behaviorWeight := "3" ;
    FileName="te.exe" | behaviorWeight := "3" ;
    FileName="sqlps.exe" | behaviorWeight := "4" ;
    FileName="sqldumper.exe" | behaviorWeight := "4" ;
    FileName="rcsi.exe" | behaviorWeight := "4" ;
    FileName="dnx.exe" | behaviorWeight := "4" ;
    FileName="appvlp.exe" | behaviorWeight := "4" ;
    FileName="dnscmd.exe" | behaviorWeight := "5" ;
    FileName="extexport.exe" | behaviorWeight := "4" ;
    FileName="gpscript.exe" | behaviorWeight := "5" ;
    FileName="le4uinit.exe" | behaviorWeight := "4" ;
    FileName="mcsconfig.exe" | behaviorWeight := "4" ;
    FileName="openwith.exe" | behaviorWeight := "3" ;
    FileName="pcwrun.exe" | behaviorWeight := "4" ;
    FileName="psr.exe" | behaviorWeight := "3" ;
    FileName="register-cimprovider.exe" | behaviorWeight := "4" ;
    FileName="runonce.exe" | behaviorWeight := "5" ;
    FileName="wab.exe" | behaviorWeight := "3" ;
    FileName="dxcap.exe" | behaviorWeight := "3" ;
    FileName="mftrace.exe" | behaviorWeight := "4" ;
    FileName="msdeploy.exe" | behaviorWeight := "4" ;
    FileName="sqltoolsps.exe" | behaviorWeight := "4" ;
    FileName="vsjitdebugger.exe" | behaviorWeight := "4" ;
}
| format(format="%s (Score: %s)\t%s", field=[execTime, behaviorWeight, CommandLine], as="executionDetails")
| groupby([aid, UserName],
    function=[
        collect([ComputerName, FileName, behaviorWeight, executionDetails]),
        count(FileName, distinct=true, as="fileCount"),
        sum(behaviorWeight, as="behaviorWeightSum")
    ], 
    limit=max
)
// adjust thresholds based on the environment
| fileCount >= 5
| behaviorWeightSum >= 29
| sort(behaviorWeight)
| drop([@timestamp, _duration, fileCount, behaviorWeightSum, behaviorWeight])

```

---

## Data Sources

| Log Provider | Event ID | Event Name      | ATT&amp;CK Data Source | ATT&amp;CK Data Component |
|--------------|----------|----------------|-----------------------|-------------------------|
| Falcon       | N/A      | ProcessRollup2 | Process               | Process Creation        |

---

## Execution Requirements
- **Required Permissions:** Normal user or attacker who can spawn processes.  
- **Required Artifacts:** Process execution logs with command-line visibility.  

---

## Considerations
- Thresholds (`fileCount >= 5` and `behaviorWeightSum >= 29`) should be **calibrated for your environment** to reduce noise.  
- False positives may occur during legitimate administrative tasks (system maintenance, patching, troubleshooting).  

---

## False Positives
- System administrators legitimately using `net.exe`, `sc.exe`, `wmic.exe` during system management.  
- Automated enterprise tools that rely on these binaries for monitoring or inventory.  

---

## Recommended Response Actions
1. Identify the initiating process and parent process.  
2. Investigate command-line arguments for suspicious flags (e.g., service manipulation, account changes).  
3. Validate execution times for anomalies (e.g., outside business hours).  
4. Correlate with network events (lateral movement, service creation).  
5. Isolate system if malicious activity is suspected.  

---

## References
- [MITRE ATT&amp;CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)  
- [MITRE ATT&amp;CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)  
- [MITRE ATT&amp;CK: T1053 – Scheduled Task](https://attack.mitre.org/techniques/T1053/)   

---

## Version History

| Version | Date       | Impact            | Notes                                                                |
|---------|------------|-------------------|----------------------------------------------------------------------|
| 1.0     | 2025-09-19 | Initial Detection | Detection of suspicious Windows command sequences leveraging LOLBins |
