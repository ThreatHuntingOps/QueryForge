
# Threat Hunting Hypothesis - Silver Fox APT abusing vulnerable drivers for EDR/AV evasion

Source intelligence: Check Point Research - “Chasing the Silver Fox: Cat & Mouse in Kernel Shadows” (Aug 28, 2025)
https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/

## Hypothesis Statement
Silver Fox APT has (or will) attempted to deploy an all‑in‑one loader on Windows endpoints in our environment that loads a Microsoft‑signed but vulnerable WatchDog Antimalware driver (amsdk.sys v1.0.600 or modified wamsdk.sys v1.1.100) to terminate protected EDR/AV processes (PP/PPL), disable defenses, and install ValleyRAT. Evidence of this activity will be observable as driver‑load events, creation of suspicious services (e.g., “Amsdk_Service”, “Termaintor”), files dropped to C:\Program Files\RunTime, DeviceIoControl usage against \.*\amsdk, and outbound C2 to infrastructure consistent with ValleyRAT.

## Why this is plausible
- CPR observed an in‑the‑wild campaign abusing an unknown‑to‑blocklists Microsoft‑signed driver (amsdk.sys 1.0.600) and later a minimally modified patched driver (wamsdk.sys 1.1.100) to evade detection and kill security processes.
- The loaders embed dual drivers (legacy Zemana driver for older OS; WatchDog driver for Win10/11) and a ValleyRAT downloader, indicating broad OS coverage and defense‑evasion.
- Attackers flipped one byte in the unauthenticated timestamp of the signature to preserve validity while changing the hash, undermining hash‑based blocklists.

## What to test (observable, testable signals)
1) Driver/Service/Filesystem
- Driver loads: amsdk.sys or wamsdk.sys loaded; creation of SERVICE_KERNEL_DRIVER named “Amsdk_Service”; NtLoadDriver usage.
- Files dropped: C:\Program Files\RunTime\RuntimeBroker.exe and Amsdk_Service.sys; folder creation “RunTime”.
- Service creation/persistence: service named “Termaintor” referencing RuntimeBroker.exe.

2) EDR/AV Kill Behavior
- DeviceIoControl calls to \.*\amsdk\anyfile with IOCTLs 0x80002010 (register) and 0x80002048 (terminate) targeting security processes.
- Sudden termination of AV/EDR protected processes (PP/PPL) without corresponding uninstall/upgrade events.
- Kernel handles opened to AV/EDR processes via IOCTL 0x8000204C.

3) Process/Module/Injection
- Execution of UPX-packed binaries named “Runtime Broker” or similar; reflective DLL loading into svchost.exe; presence of modules with Chinese internal names (上线模块.dll, 登录模块.dll).
- Anti-VM/anti-sandbox checks and geo/ISP checks to ip-api[.]com/json prior to payload retrieval.

4) Network (ValleyRAT)
- XOR-encrypted C2 using key 363636003797e4383a36; C2 IPs/ports stored and used in reverse order (per report); C2 hosted in China (cloud/web services).

## Scope and prioritization
- Prioritize Windows 10/11 endpoints with recent unexplained EDR/AV service stops or tamper‑protection alerts.
- Include legacy Win7/2008 systems due to fallback Zemana driver path.

## Validation steps
- Correlate driver load events with immediate EDR/AV process terminations.
- Verify creation of RunTime folder and service entries; hash/metadata of dropped drivers; presence of Microsoft signature yet mismatching known hashes.
- Memory forensics on affected hosts for ValleyRAT artifacts and svchost.exe injections; decrypt sample C2 using the published XOR key.

## Potential data sources
- EDR telemetry (process, module loads, tamper protection events)
- Sysmon (Event ID 6 DriverLoad; 1/7 process creation/image loads; 3 network)
- Windows Security logs (service creation 4697, driver/service changes)
- ETW/Kernel trace for DeviceIoControl, NtLoadDriver
- Network proxy/firewall logs; DNS

## Hunt decision criteria
- Confirmed: Any combination of (a) amsdk.sys or modified wamsdk.sys loaded plus (b) PP/PPL security process kills and (c) artifacts in C:\Program Files\RunTime or services “Amsdk_Service”/“Termaintor”, or (d) ValleyRAT indicators.
- Benign/FP: Legitimate Watchdog deployments with patched drivers that do not exhibit PP/PPL termination behavior or post‑driver ValleyRAT activity.


