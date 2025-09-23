# Silver Fox APT - Multi-Stage Attack Chain Correlation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Analytics Metadata

- **ID:** CorrelationRule-Windows-SilverFox-Correlation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Analytics

This correlation rule detects the complete multi-stage attack chain of Silver Fox APT by correlating events across initial execution, driver loading, security process termination, and C2 communication. It requires the presence of security process termination (Stage 3) along with at least one other stage to reduce false positives while providing high-fidelity detection of the full attack sequence. Detected behaviors include:

- Stage 1: Execution of RuntimeBroker.exe from persistence folder
- Stage 2: Loading of vulnerable drivers (amsdk.sys, wamsdk.sys, ZAM.exe)
- Stage 3: Termination of security/AV processes
- Stage 4: C2 communications to China or geolocation services

These techniques are associated with malicious file execution, KPP bypass, impairing defenses, and web protocol C2.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1204       | T1204.002    | User Execution: Malicious File                |
| TA0005 - Defense Evasion     | T1574       | T1574.013    | Hijack Execution Flow: KPP Bypass            |
| TA0005 - Defense Evasion     | T1562       | T1562.001    | Impair Defenses: Disable or Modify Tools     |
| TA0011 - Command and Control | T1071       | T1071.001    | Application Layer Protocol: Web Protocols     |

---

## Query Logic

This correlation rule aggregates events by causality chain and hostname, counting occurrences in each stage. It flags the presence of each stage and requires Stage 3 (security process termination) plus at least one other stage for detection. This ensures high confidence in identifying the full attack chain.

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false 

| dataset = xdr_data 

| filter ( 
    // Stage 1: Initial execution from persistence folder 
    (event_type = ENUM.PROCESS 
     and actor_process_image_name = "RuntimeBroker.exe" 
     and actor_process_image_path contains "\Program Files\RunTime\") 
    
    or 
    
    // Stage 2: Vulnerable/patched driver load 
    (event_type = ENUM.LOAD_IMAGE 
     and (action_module_path contains "amsdk.sys" 
          or action_module_path contains "wamsdk.sys" 
          or action_module_path contains "ZAM.exe") 
     and causality_actor_process_image_path contains "\Program Files\RunTime\") 
    
    or 
    
    // Stage 3: Security process termination (EDR/AV kill) 
    (event_type = ENUM.PROCESS 
     and event_sub_type = ENUM.PROCESS_STOP  
     and action_process_image_name in ( 
         // List of security/AV processes being stopped (targeted processes)
         "360netcfg64.exe", "MsMpEng.exe", "19811-FalconSensor_Windows.x64.exe", "SecurityHealthService.exe", "MpDlpService.exe", "MpCmdRun.exe", "SecurityHealthSystray.exe", "smartscreen.exe", "360realpro.exe",
         "cyserver.exe", "cytool.exe", "xdrhealth.exe", "360rp.exe", "360rps.exe", "360sd.exe", "360sdSetup.exe", "360sdToasts.exe", "360sdrun.exe", "360sdsf.exe", "360sdupd.exe", "360speedld.exe", "360tray.exe", 
         "BGADefMgr.exe", "BrowserPrivacyAndSecurity.exe", "CertImporter-1684.exe", "Client.exe", "ConfigSecurityPolicy.exe", "DSMain.exe", "DlpUserAgent.exe", "DumpUper.exe", "Fetion.exe", 
         "HipsDaemon.exe", "HipsTray.exe", "MSPCManager.exe", "MSPCManagerCore.exe", "MSPCManagerService.exe", "MipDlp.exe", "MpCopyAccelerator.exe", "MpDlpCmd.exe", 
         "MultiTip.exe", "NewIDView.exe", "NisSrv.exe", "PCMAutoRun.exe", "QMAIService.exe", "QMDL.exe", "QMFloatWidget.exe", "QQPCExternal.exe", "QQPCMgrUpdate.exe", 
         "QQPCPatch.exe", "QQPCRTP.exe", "QQPCSoftCmd.exe", "QQPCSoftMgr.exe", "QQPCTray.exe", "QQRepair.exe", "RMenuMgr.exe", "SecurityHealthHost.exe", "SysCleanProService.exe", 
         "SysInspector.exe", "VolSnapshotX64.exe", "ZhuDongFangYu.exe", "activeconsole", "anti-malware", "antimalware", "avpia.exe", "avpvk.exe", "callmsi.exe", "eCapture.exe", "eComServer.exe", "ecls.exe", 
         "ecmd.exe", "ecmds.exe", "eeclnt.exe", "egui.exe", "eguiProxy.exe", "feedback.exe", "feedbackwin.exe", "kailab.exe", "kassistant.exe", "kassistsetting.exe", "kauthorityview.exe", "kavlog2.exe", 
         "kcddltool.exe", "kcleaner.exe", "kcrm.exe", "kctrlpanel.exe", "kdf.exe", "kdinfomgr.exe", "kdownloader.exe", "kdrvmgr.exe", "kdumprep.exe", "kdumprepn.exe", "keyemain.exe", "kfixstar.exe", 
         "kfloatmain.exe", "khealthctrlspread.exe", "kinst.exe", "kintercept.exe", "kislive.exe", "kismain.exe", "kldw.exe", "kmenureg.exe", "knewvip.exe", "knotifycenter.exe", "krecycle.exe", "kscan.exe", 
         "kschext.exe", "kscrcap.exe", "ksetupwiz.exe", "kslaunch.exe", "kslaunchex.exe", "ksoftmgr.exe", "ksoftmgrproxy.exe", "ksoftpurifier.exe", "kteenmode.exe", "ktrashautoclean.exe", "kupdata.exe", 
         "kwebx.exe", "kwsprotect64.exe", "kwtpanel.exe", "kxecenter.exe", "kxemain.exe", "kxescore.exe", "kxetray.exe", "kxewsc.exe", "mpextms.exe", "packageregistrator.exe", "plugins-setup.exe", 
         "plugins_nms.exe", "qmbsrv.exe", "rcmdhelper.exe", "rcmdhelper64.exe", "remove_incompatible_applications.exe", "restore_tool.exe", "safesvr.exe", "securityhealthsystray.exe", 
         "sysissuehat.exe", "troubleshoot.exe", "uni0nst.exe", "uninstallation_assistant_host.exe", "upgrade.exe", "vssbridge64.exe", "webx.exe", "webx_helper.exe", "wmiav.exe", "wsctrlsvc.exe"
     )
     // Exclude legitimate stopping processes to reduce noise
     and actor_process_image_name not in (
         "svchost.exe", "services.exe", "taskmgr.exe", "powershell.exe", "cmd.exe", "explorer.exe", 
         "System", "wininit.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "smss.exe", "spoolsv.exe", 
         "wuauserv.exe", "msiexec.exe", "rundll32.exe"
     )
     // Anomaly checks to catch potential abuse of excluded processes. Flag non-standard paths
     and actor_process_command_line not contains "C:\Windows\System32\"
     and  actor_effective_username != "NT AUTHORITY\SYSTEM" // Exclude system-level actions; confirm field name
    ) 
    
    or 
    
    // Stage 4: C2 communication 
    (event_type = ENUM.NETWORK 
     and actor_process_image_path contains "\Program Files\RunTime\" 
     and (
         dst_action_country = "China" 
         or dns_query_name contains "ip-api.com" 
         or dns_query_name contains "ipinfo.io" 
         or dns_query_name contains "ipapi.co" 
         or dns_query_name contains "ipgeolocation.io"
     )) 
) 

// Aggregate events per causality chain 
| comp 
    sum(if(event_type = ENUM.PROCESS and actor_process_image_name = "RuntimeBroker.exe", 1, 0)) as stage_1_count,
    sum(if(event_type = ENUM.LOAD_IMAGE, 1, 0)) as stage_2_count,
    sum(if(event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_STOP, 1, 0)) as stage_3_count,
    sum(if(event_type = ENUM.NETWORK, 1, 0)) as stage_4_count,
    min(event_timestamp) as first_event,
    max(event_timestamp) as last_event,
    count() as total_events
    by causality_actor_causality_id, agent_hostname

// Stage presence flags 
| alter stage_1_present = to_integer(if(stage_1_count > 0, "1", "0"))
| alter stage_2_present = to_integer(if(stage_2_count > 0, "1", "0"))
| alter stage_3_present = to_integer(if(stage_3_count > 0, "1", "0"))
| alter stage_4_present = to_integer(if(stage_4_count > 0, "1", "0"))

// Distinct stages = sum of presence flags 
| alter distinct_stages = add(add(stage_1_present, stage_2_present), add(stage_3_present, stage_4_present))

// Require Stage 3 present AND at least one more stage 
| filter stage_3_present = 1 and distinct_stages >= 2

| fields causality_actor_causality_id, agent_hostname,
    stage_1_count, stage_2_count, stage_3_count, stage_4_count,
    distinct_stages, total_events, first_event, last_event

| sort desc distinct_stages, asc first_event
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation/Stop  |
| Cortex XSIAM|    xdr_data       | Module             | Module Load            |
| Cortex XSIAM|    xdr_data       | Network Traffic    | Network Connection Creation |

---

## Execution Requirements

- **Required Permissions:** Various, depending on stage (execution, driver load, process kill, network).
- **Required Artifacts:** Process logs, module load logs, network logs, causality chain data.

---

## Considerations

- Review the causality chain for the full sequence of events.
- Correlate with host activity to confirm compromise.
- Investigate each stage for legitimacy and context.
- Validate against threat intelligence for known Silver Fox indicators.

---

## False Positives

False positives may occur if:

- Legitimate processes stop security software (e.g., during updates).
- Benign driver loads or network connections.
- System maintenance activities mimicking stages.

---

## Recommended Response Actions

1. Investigate the full attack chain and causality.
2. Analyze each stage for malicious intent.
3. Isolate affected endpoints immediately.
4. Review and restore security processes.
5. Block associated IPs, domains, and drivers.

---

## References

- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1574.013 – Hijack Execution Flow: KPP Bypass](https://attack.mitre.org/techniques/T1574/013/)
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-09-04 | Initial Detection | Created correlation rule to detect Silver Fox APT multi-stage attack chain                |
