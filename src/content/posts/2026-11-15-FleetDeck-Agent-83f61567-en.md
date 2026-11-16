---
title: "Malware Analysis: FleetDeck Agent (PE · exe · 83f61567)"
published: 2026-11-15
draft: false
description: "Gray/PUA (high confidence): FleetDeck Agent · rat/implant · difficulty medium · dynamic sandbox + static decompilation"
tags: ["FleetDeck Agent", "rat", "implant", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-15-FleetDeck-Agent-83f61567"
---

> [!CAUTION]
> **Verdict: Gray/PUA** · Family **FleetDeck Agent** · Confidence **High**
> 
> Aliases: FleetDeck RMM, Fleetdeck Agent Installer, fleetdeck_agent_svc
> 
> The sample is a FleetDeck Agent installer validly code-signed by Fleetdeck Inc. (Go 1.20.14); after installation it creates a LocalSystem autostart service and drops fleetdeck_agent_svc.exe, with remote session/command, firewall-rule management and self-update capabilities. In this sandbox no file encryption, credential theft, process injection or complete C2 session was observed, so it is judged a potentially unwanted remote-management tool (PUA) rather than a typical malicious payload.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **FleetDeck Agent** · aliases FleetDeck RMM, Fleetdeck Agent Installer, fleetdeck_agent_svc |
| Confidence | **High** |
| Behavior class | rat · implant |
| Difficulty | medium |
| First seen | 2026-11-15 00:08:05 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/83f61567e0eac6b8b9adcadb18e3c80f56a8c486b0fbc393ea1e12c04d3caa78/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Install embedded MSI</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1218.007</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Register autostart service</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Start and call update endpoint</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Use DNS-over-TLS</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Create firewall allow rules</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.004</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `83f61567e0eac6b8b9adcadb18e3c80f56a8c486b0fbc393ea1e12c04d3caa78` |
| MD5 | _not recorded_ |
| Size | 4,391,192 bytes (4.2 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**8** behaviors in total, each backed by evidence; **3** are statically available and **5** were obtained through dynamic analysis.

### 1. Install embedded MSI

`T1218.007` · Confidence **High** · Dynamic

The installer drops the embedded MSI and calls msiexec to install it; msiexec creates C:\Program Files (x86)\FleetDeck Agent\fleetdeck_agent_svc.exe and writes the uninstall registry entry.

> **Evidence**: Dynamic: msiexec.exe process creation + File created: C:\Program Files (x86)\FleetDeck Agent\fleetdeck_agent_svc.exe; static: embedded MSI at 0x1b9460, #agent_svc.cab at 0x1be460
> 
> **Source**: `ev-000034` · `ev-000030` · `ref:7834e20d29`

### 2. Register autostart service

`T1543.003` · Confidence **High** · Dynamic

The MSI creates service FleetDeck Agent Service with ImagePath pointing at the dropped agent, Start=2 automatic, running as LocalSystem (resident with system privileges).

> **Evidence**: System telemetry Event 7045 / service table: FleetDeck Agent Service, LocalSystem, Start=2; registry HKLM\System\CurrentControlSet\Services\FleetDeck Agent Service\ImagePath and Start writes
> 
> **Source**: `ev-000030` · `ev-000034` · `ref:7834e20d29`

### 3. Start and call back to update endpoint

`T1071.001` · Confidence **High** · Dynamic

The service starts with -deploymentID b66c6e71-8ec2-49d4-915e-a8c910128585 -askForName=0, continuously resolves agentupdate[.]fleetdeck[.]io and initiates 443/TCP connections; no complete HTTP/TLS request-response was captured.

> **Evidence**: Dynamic: fleetdeck_agent_svc.exe pid 7824 made repeated DNS queries for agentupdate[.]fleetdeck[.]io and TCP 192.0.2[.]123:443 connections; command line contains deploymentID
> 
> **Source**: `ev-000030` · `ev-000033` · `ref:7834e20d29`

### 4. Use DNS-over-TLS

`T1071.004` · Confidence **High** · Dynamic

The agent embeds robustdns/miekg-dns and after startup initiates DNS-over-TLS connections to 1.1.1[.]1, 8.8.8[.]8 and 9.9.9[.]9 on 853/TCP, bypassing local plaintext DNS observation.

> **Evidence**: Dynamic: repeated TCP connections to 1.1.1[.]1:853, 8.8.8[.]8:853, 9.9.9[.]9:853; static: fleetdeck[.]io/prototype3/go-libs/robustdns, github[.]com/miekg/dns
> 
> **Source**: `ev-000030` · `ev-000033` · `ref:7834e20d29`

### 5. Create firewall allow rules

`T1562.004` · Confidence **High** · Dynamic

During installation/service startup it runs New-NetFirewallRule through PowerShell; the agent implements AddFirewallRule/UpdateFirewallRule/Remove-NetFirewallRule internally, used to allow/hide the management channel.

> **Evidence**: Dynamic: C:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe -Command "New-NetFirewallRule…" (2 times); static: agent 0x36ef01 "Remove-NetFirewallRule -Name '%s'" and svcutil.AddFirewallRule
> 
> **Source**: `ev-000030` · `ev-000033` · `ref:7834e20d29`

### 6. Retain safe-mode exception

`T1562.009` · Confidence **Medium** · Static

The agent contains logic to add itself to the safe-boot exception list (Added safe boot exception), so the service can still start in safe mode; this write was not observed actually executing in this run.

> **Evidence**: Static: agent file offset 0x36ee1a string "Added safe boot exception for: %v"
> 
> **Source**: `ev-000033`

### 7. Embedded remote session control

`T1134` · Confidence **Medium** · Static

The agent contains WTS session enumeration, token duplication/setting (nativeWTSEnumerateSessions, nativeDuplicateTokenEx, nativeSetTokenInformation, sendSAS), PowerShell invocation and force-kill-process logic, allowing it to enter the interactive desktop for remote operations; no remote command delivery was observed in this run.

> **Evidence**: Static: agent symbols svcutil.nativeWTSEnumerateSessions/nativeDuplicateTokenEx/nativeSetTokenInformation, string 0x372ce2 "Forcibly terminating process with PID: %v"; dynamically only the service itself ran
> 
> **Source**: `ev-000033`

### 8. Self-update by replacing the service

`T1105` · Confidence **Medium** · Static

The updater fetches version information and update packages from agentupdate[.]fleetdeck[.]io, and after extraction replaces itself through ReplaceSvcExe/RestartSvc and restarts; it includes executable integrity verification.

> **Evidence**: Static: module fleetdeck[.]io/prototype3/go-libs/updater (request/loadLatestVersion/unzip/Update/AsyncUpdate), svcutil.ReplaceSvcExe/RestartSvc, 0x374370 "Could not validate agent executable integrity"
> 
> **Source**: `ev-000033` · `ev-000030`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://agentupdate[.]fleetdeck[.]io` | 443 | download | Static | ⏳ Not observed |

### Host

**Dropped paths**

- `%ProgramFiles(x86)%\FleetDeck Agent\fleetdeck_agent_svc.exe`
- `%TEMP%\*.msi (temporary MSI generated during installation)`

**Registry**

- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{91D2B1CB-907C-4D2E-BA94-4205540E5C02}`
- `HKLM\SYSTEM\CurrentControlSet\Services\FleetDeck Agent Service`

**Services**

- `FleetDeck Agent Service`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `deployment_id` | `b66c6e71-8ec2-49d4-915e-a8c910128585` | Yes | Static |
| `c2_hosts` | `agentupdate[.]fleetdeck[.]io` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `-` | No | Static |
| `service_name` | `FleetDeck Agent Service` | Yes | Static |
| `install_path` | `%ProgramFiles(x86)%\FleetDeck Agent\fleetdeck_agent_svc.exe` | Yes | Static |
| `product_code` | `{91D2B1CB-907C-4D2E-BA94-4205540E5C02}` | Yes | Static |
| `dns_resolvers` | `1.1.1[.]1, 8.8.8[.]8, 9.9.9[.]9 (TCP/853 DNS-over-TLS)` | No | Dynamic |
| `encryption_algo` | `TLS 1.2/1.3 (Go crypto/tls)` | No | Static |
| `mutex` | `-` | No | Static |
| `campaign_id` | `-` | No | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not call it ransomware, a stealer or a miner: no file encryption, credential/browser-data theft or mining behavior was observed; its main body is a remote-management installer.
- Do not say it performed process injection or process hollowing: memory scanning found no hollowing/hook/IAT anomalies, and no injection behavior was observed dynamically.
- Do not describe agentupdate[.]fleetdeck[.]io as a C2 with an established session: only DNS queries and TCP 443 connection attempts were seen, with no complete request/response.
- Do not say it uses a custom encryption algorithm: communication uses Go's standard crypto/tls, and no custom encryption implementation was seen.
- Do not conclude from symbol names alone that the safe-mode exception was written or tokens were stolen: these two are static capability evidence only, and execution was not observed in this run.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. No complete HTTP/TLS request or response was obtained; the C2 is confirmed only as DNS and TCP 443 connection attempts to agentupdate[.]fleetdeck[.]io, marked static + pending_dynamic_verify per the rules.
2. deploymentID b66c6e71-8ec2-49d4-915e-a8c910128585 sits in tail padding of the signing certificate table and is not covered by Authenticode; it cannot be used to determine the actual tenant or the dropper's intent.
3. The DNS-over-TLS targets 1.1.1[.]1/8.8.8[.]8/9.9.9[.]9 are redirected in the isolated network, so real resolution results could not be obtained and the main management-channel domain was not recovered.
4. The safe-mode exception, token duplication/interactive-session control and self-update replacement have only static string/symbol evidence; no remote commands or update downloads were observed in this run.
5. No kernel driver, browser injection, data exfiltration or lateral movement behavior was observed.
6. The sample is a prototype3 (devel) build and cannot be mapped to an official FleetDeck release version.

## Evidence Index

<details>
<summary>Expand 18 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | Sample SHA256/MD5/SHA1 and size |
| `ev-000002` | scan.imphash | imphash=9cbefe68f395e67356e2a5d8d1b285c0 |
| `ev-000005` | scan.entropy | .data entropy 7.901 (high, contains embedded MSI/cab) |
| `ev-000009` | scan.entropy | .rsrc entropy 7.867 (high) |
| `ev-000018` | Hash and fingerprint | Unpacked agent service sha256=bd0285b4… size 6256920 |
| `ev-000019` | scan.rich | Agent is an MSVC build, richhash=22d65b2322a014b5eda24983a4380345 |
| `ev-000026` | Sample triage | Agent has 0 imported symbols (Go static-linking trait), not typically packed |
| `ev-000030` | evidence.record | Dynamic telemetry summary: service install/start, deploymentID command line, DNS/443, DoT/853, firewall rules |
| `ev-000031` | evidence.record | Embedded MSI/cab/agent offsets and hashes, deployment-ID location |
| `ev-000032` | evidence.record | Authenticode verification valid, signer Fleetdeck Inc. |
| `ev-000033` | evidence.record | Agent capability string offsets and Go module/symbols |
| `ev-000034` | evidence.record | Embedded MSI product/service/command-line table entries |
| `ref:7834e20d29` | Dynamic analysis platform | Dynamic sandbox polling timeline: sample, csc.exe, service and network observations |
| `ref:80315c4400` | Sample triage | Triage: PE32 GUI, 7 sections, low packing score |
| `ref:fe56f0f3e3` | Import table parsing | Imports only 39 kernel32 symbols (Go runtime) |
| `ref:a4399318ab` | PE structure parsing | Entry 0x60240, imagebase 0x400000, includes SECURITY directory |
| `telemetry:83f61567` | Dynamic telemetry | Dynamic telemetry recorded: new services 1 (FleetDeck Agent Service); certificates added 2; monitoring components registry events 6; monitoring components process/file events 144; ETW short-lived process events 1; system service events 1; filtered tool/system noise 31 |
| `etw:83f61567:5228` | Process event monitoring | Short-lived process event: 83f61567e0eac6b8b9adcadb18e3c80f56a8c486b0fbc393ea1e12c04d3caa78.exe (pid 5228; MD5=941B52AAEAADA152162B6581475F84D8,SHA256=83F61567E0EAC6B8B9ADCADB18E3C80F56A8C486B0FBC393EA1E12C04D3CAA78,IMPHASH=9CBEFE68F395E67356E2A5D8D1B285C0) |

</details>

---

_This report's sample is not public, IOCs are defanged, and it is for security research only._
