# Suspected WMIExec Abuse Hunt Query Documentation

## Overview
This hunt query detects multiple sub-processes under `WmiPrvSE.exe` writing to the same file, a behavior commonly associated with Impacket’s WMIExec tool. WMIExec enables threat actors to move laterally and execute commands on remote systems, often resulting in a sequence of interactive shell behaviors. This detection complements sensor-based detections and is designed to surface activity indicative of interactive sessions, even those that are slow and persistent.

---

## Hunt Query Logic

- Retrieves all `WmiCreateProcess` events from the `base_sensor` repository.
- Filters for executions of `cmd.exe`.
- Uses regex to extract the WMI command and the redirected file from the command line.
- Excludes benign command lines (e.g., simple directory changes or netstat).
- Calculates the time delta between the file timestamp and the event timestamp to identify interactive sessions (duration > 1s).
- Groups by agent ID, redirect file, and IP addresses, collecting activity and counting unique commands and process IDs.
- Surfaces cases where there are multiple unique commands and process IDs writing to the same file, which is highly indicative of WMIExec abuse.

---

## Hunt Query Syntax

**Query Language:** LogScale Query Language (Humio)  
**Platform:** LogScale (Humio)

```humio
#repo="base_sensor" #event_simpleName="WmiCreateProcess" 
| FileName="cmd.exe" 
| regex("^cmd.exe /Q /c (?<wmic_command>.*) 1>(?<redirect_file>.+?__(?<_file.timestamp>\d+\.\d+))\s", field="CommandLine", flags="i") 
| CommandLine =~ !in(values=["*/Q /c cd  1>*","*/Q /c cd \ 1>*","*/Q /c netstat -anop TCP*"]) 
| _time := formatTime("%Q") 
| _time.file := parseTimestamp(field=_file.timestamp, format=UnixTimeSeconds) 
| _time.delta := _time - _time.file 
| test(_time.delta>1000) 
| _time := formatTime("%Y/%m/%d %H:%M:%S", field=_time) 
| wmi_activity := format(format="[%s] %s", field=[_time, wmic_command]) 
| groupBy([aid, redirect_file, LocalAddressIP4, RemoteAddressIP4], function=[ 
  collect(wmi_activity), 
  count(field=wmic_command, as=total_commands, distinct=true), 
  count(field=TargetProcessId, as=total_pids, distinct=true) 
  ], limit=max) 
| total_commands>1 total_pids>1
```

---

## Data Sources

| Log Provider | Event Name        | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|-------------------|---------------------|------------------------|
| LogScale     | WmiCreateProcess  | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process creation events from Windows endpoints.
- **Required Artifacts:** Process execution logs, command line arguments, file write events.

---

## Considerations

- The time period for this search should be greater than 3 hours to detect slow but persistent actors.
- Duration greater than 1 second (delta between file timestamp and event timestamp) is likely to identify interactive sessions.
- Due to the function of LogScale's distinct count, there is a small likelihood for false positives.
- Review the sequence of commands and the context of the redirect file for signs of lateral movement or interactive shell activity.

---

## False Positives

False positives may occur if:
- Legitimate system activity results in multiple processes writing to the same file in a similar pattern.
- Automation or management tools use WMI in ways that mimic interactive sessions.

---

## Recommended Response Actions

1. Investigate the sequence of commands and the redirect file for malicious intent.
2. Validate the legitimacy of the activity and its source.
3. Review related process activity, user context, and network connections.
4. Isolate affected systems if malicious activity is confirmed.

---

## References
- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [Impacket: WMIExec](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py)
- [Humio: count() Function Accuracy](https://library.humio.com/data-analysis/functions-count.html#functions-count-accuracy)

---

## Version History
| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-06 | Initial Detection | Created hunt query to detect suspected WMIExec abuse                                       |
