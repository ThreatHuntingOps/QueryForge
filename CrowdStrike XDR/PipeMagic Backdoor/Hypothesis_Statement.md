
# Threat Hunting Hypothesis: PipeMagic Backdoor

## Source
- **Threat Intelligence:** [Kaspersky Securelist – Evolution of the PipeMagic backdoor: from the RansomExx incident to CVE-2025-29824](https://securelist.com/pipemagic/117270/)
- **Date:** August 2025

## Hypothesis Statement
If our environment has been targeted by operators deploying the PipeMagic backdoor, then we will observe artifacts consistent with recent campaigns (2024–2025), including:
- Initial access via trojanized loaders (e.g., fake ChatGPT client built with Rust/Tauri/Tokio) or DLL hijacking alongside legitimate binaries (e.g., Google Chrome updater), and/or MSBuild execution of a malicious .mshi C# project.
- Local inter-process communication artifacts such as randomly generated named pipes of the form `\.\pipe\1.<16-byte-hex>` or hardcoded variants (e.g., `\.\pipe\magic3301`, `\.\pipe\0104201.%d, `), with a localhost listener at `127.0.0.1:8082` used to bridge to the pipe.
- Staging and module retrieval from attacker-controlled Azure cloud domains (e.g., `aaaaabbbbbbb.eastus.cloudapp.azure.com`).
- Post-exploitation credential access marked by LSASS dumping executed with a renamed ProcDump masquerading as `dllhost.exe` and command-line flags consistent with ProcDump usage.

Therefore, targeted collection and analysis across endpoints, network, and identity telemetry should reveal these indicators if PipeMagic activity is present.

## Rationale (Intelligence Basis)
Kaspersky reports continuing PipeMagic operations in 2024–2025 against Middle Eastern and Brazilian organizations, reusing 2022 tradecraft with new loaders and modules:
- Loaders: MSHelp Index (.mshi) invoking MSBuild; Rust/Tauri/Tokio fake ChatGPT app; DLL hijacking with malicious `googleupdate.dll` decrypting AES-CBC payload.
- Backdoor behavior: generates random 16-byte pipe names in the form `\.\pipe\1.<16-byte-hex>`; maintains a localhost interface on `127.0.0.1:8082`; downloads plugins from Azure-hosted C2.
- Modules: asynchronous I/O file ops plugin; a loader establishing `\\.\pipe\test_pipe20.%d` to stage 64-bit payloads; injector that patches AMSI (AmsiScanString/Buffer) and launches .NET payloads via `mscoree.dll` for CLR versions 2.0/4.0.
- Post-exploitation: LSASS memory dumping using ProcDump renamed to `dllhost.exe`, enabling credential theft and lateral movement.

These behaviors are specific, recent, and testable in enterprise telemetry.

## Test Plan (Data-Driven, Actionable)

### 1) Initial Access and Loader Execution
Data sources: EDR process telemetry, Windows Event Logs (4688), Sysmon (Event 1), file creation events
- Look for executions of MSBuild spawning from cmd/powershell loading `.mshi` in non-standard paths (e.g., `C:\Windows\help\metafile.mshi`).
  - Detection logic: Parent `cmd.exe` or `powershell.exe` -> `msbuild.exe` with argument matching `*.mshi`.
- Identify executions of suspicious `chatgpt.exe` without user functionality (blank window) followed by immediate child process or memory injection behavior.
  - Correlate binary metadata: Rust/Tauri/Tokio strings; libaes usage; MD5s from IoCs.
- DLL hijack patterns: Legitimate updaters (e.g., Chrome updater) loading a side-by-side `googleupdate.dll` from writable directories.
  - Detect ImageLoad events for `googleupdate.dll` where the loaded path is not the expected signed vendor location; flag AES-CBC decryption routines in memory (key/IV artifacts where possible).

### 2) Named Pipes and Localhost Bridge
Data sources: EDR named pipe telemetry, Sysmon (Event 17–18), Windows pipe auditing, netstat captures
- Hunt for named pipes matching:
  - `\.\pipe\magic3301`
  - `\.\pipe\0104201.%d`
  - `\\.\pipe\test_pipe20.%d`
- Identify processes that open these pipes and simultaneously bind or connect to `127.0.0.1:8082`.
  - Correlate process image with unsigned/suspicious PE that lacks GUI despite GUI subsystem, or loaders described above.

### 3) C2 and Module Retrieval
Data sources: Proxy/Firewall logs, DNS logs, EDR network telemetry
- Query for any egress to `*.eastus.cloudapp.azure.com`, specifically `aaaaabbbbbbb.eastus.cloudapp.azure.com`.
  - Inspect TLS SNI, HTTP Host headers, and timing post loader execution.
- Alert on unusual Azure CloudApp patterns immediately following creation of suspicious named pipes.

### 4) AMSI Tampering and .NET Injection
Data sources: EDR memory telemetry, Sysmon (Event 7), PowerShell/AMSI logs, Windows Event Logs
- Detect in-memory patching of `amsi.dll` functions `AmsiScanString`/`AmsiScanBuffer` to stubs returning 0.
  - Look for RWX changes on amsi memory regions; API calls like `VirtualProtect` targeting amsi function addresses.
- Monitor `mscoree.dll` loads in unexpected processes, version negotiation for CLR 4.0.30319 or 2.0.50727, followed by reflective .NET assembly execution.

### 5) Credential Access via ProcDump Masquerade
Data sources: Process creation logs, Sysmon (Event 10), command-line auditing, file creation on disk
- Identify `dllhost.exe` with command-line flags incompatible with the real Windows `dllhost.exe`, e.g., `-accepteula -r -ma lsass.exe <path>`.
  - Map the image path and signature; true `dllhost.exe` should not accept ProcDump flags.
- Look for LSASS dumps in user-writable paths (e.g., `%APPDATA%\FoMJoEqdWg`).

## Environmental Scoping and Exclusions
- Scope to Windows endpoints (x86/x64) and servers with developer tooling where MSBuild may legitimately run.
- Exclude legitimate MSBuild pipelines by parent/child lineage and signed project locations; focus on MSBuild invoked from user shells targeting `.mshi` in OS folders.
- Exclude legitimate Chrome updater operations by verifying signed DLL load paths; flag unsigned or side-loaded `googleupdate.dll`.

## Success Criteria (Falsifiable/Testable)
- Confirmed presence of any of the following elevates hypothesis confidence:
  1) Matches on PipeMagic-style pipe names with correlated 127.0.0.1:8082 activity by the same process.
  2) Outbound connections to `aaaaabbbbbbb.eastus.cloudapp.azure.com` temporally linked to suspected loader execution.
  3) Evidence of AMSI patching and subsequent .NET reflective load via `mscoree.dll` in the same process tree.
  4) LSASS dump creation via a binary named `dllhost.exe` using ProcDump flags.
- If none of these artifacts are observed across a representative sample and historical windows (e.g., 30–90 days), the hypothesis is weakened.

## Related IoCs (from Securelist)
- Domain: `aaaaabbbbbbb.eastus.cloudapp.azure.com`
- Hashes:
  - `5df8ee118c7253c3e27b1e427b56212c` (metafile.mshi)
  - `60988c99fb58d346c9a6492b9f3a67f7` (chatgpt.exe)
  - `7e6bf818519be0a20dbc9e5728c6` (chatgpt.exe)
  - `e3c8480749404a45a61c39d9c3152251` (googleupdate.dll)
  - `1a119c23e8a71bf70c1e8edf948d5181` (backdoor PE)
  - `bddaf7fae2a7dac37f5120257c7c11ba`


