---
title: "Malicious sample analysis: DeviceSync Stealer (internal tag nblx-v2) (PE · exe · 494610ff)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: low): DeviceSync Stealer (internal tag nblx-v2) · stealer/loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["DeviceSync", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-DeviceSync-Stealer-内部标识-nblx-v2-494610ff"
---

> [!WARNING]
> **Verdict: malicious** · Family **DeviceSync Stealer (internal tag nblx-v2)** (unconfirmed) · Confidence **low**
> 
> Aliases: Device Sync, DeviceSync.dll, DSYNC, nblx-v2
> 
> Static analysis recovered the complete information-stealing implementation: a .NET program masquerading as the "Device Sync" sync component, with built-in collection of cookies, passwords, autofill, credit cards and history from Chrome/Edge/Brave/Opera and Firefox, plus IElevator COM to decrypt App-Bound encrypted data; it also collects clipboard/screen/wallet/registry hive data, applies Defender exclusions and AMSI/ETW patches, persists via HKCU Run, exfiltrates over HTTPS (pinned RSA public key) with a DGA fallback, and drops/retrieves follow-on payloads from the server. In the dynamic sandbox the .NET payload actually loaded and stayed resident, and stealing and self-check symbols such as HarvestBrowserAsync/GuardPolicy are visible in process memory; because the runtime environment was identified as virtualized, collection and outbound communication did not occur within the observation window.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **DeviceSync Stealer (internal tag nblx-v2)** · Aliases Device Sync, DeviceSync.dll, DSYNC, nblx-v2 · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | stealer · loader |
| Difficulty | hard |
| First seen | 2026-11-24 23:27:58 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/494610ff80608b4f0ca922fb27a8e1a2cd9d896ee4ae03384cf405faf4a6e3fc/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Masquerades as device sync</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Harvests browser credentials</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Bypasses app-bound encryption</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1548</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Collects wallet and desktop data</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Env self-check, delayed dwell</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `494610ff80608b4f0ca922fb27a8e1a2cd9d896ee4ae03384cf405faf4a6e3fc` |
| MD5 | _Not recorded_ |
| Size | 598,016 bytes (584.0 KB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **11** behaviors in total, each backed by evidence; **9** are statically available and **2** were obtained through dynamic analysis.

### 1. Masquerades as a device sync component

`T1036.005` · Confidence **high** · Static

With a forged version resource (Device Sync / DeviceSync.dll / 4.3.73[.]0) and three randomly named sections (fgFmU, tFXPS, NtWES), it masquerades as ordinary sync software but is actually a .NET infostealer.

> **Evidence**: VS_VERSION_INFO in the resource section: CompanyName=Device Sync, OriginalFilename=DeviceSync.dll; the PE header has no import table, entry RVA=0, and section names are random
> 
> **Source**: `ref:2909583825` · `ref:57bf27c1c3` · `ev-000006`

### 2. Harvests browser credentials

`T1555.003` · Confidence **high** · Static

It collects Cookie, Login Data, Web Data, History and Local State item by item from the User Data and Firefox profile directories of Chrome/Edge/Brave/Opera/Chromium, and exports them through two paths: a headless-browser DevTools path and direct SQLite reads.

> **Evidence**: UTF-16 literals '\Network\Cookies', '\Login Data', '\Web Data', 'Local State', 'chrome://settings/passwords'; method names HarvestBrowserAsync/ReadCookiesAsync/ReadLoginsAsync; SQLite query 'SELECT url, title, visit_count, last_visit_time FROM urls ... LIMIT 2000'
> 
> **Source**: `ev-000006` · `ref:2909583825`

### 3. Bypasses app-bound encryption

`T1548` · Confidence **high** · Static

It enumerates IElevatorChrome/IElevatorEdge/IElevatorBrave and their V2 interfaces, elevates a helper process via --elevated-caller to decrypt Chrome v20 App-Bound encrypted cookies and passwords through COM calls, and falls back to database parsing on failure.

> **Evidence**: literals IElevatorChrome2/IElevatorEdge2/IElevatorBrave2, CoCreateInstance/CoSetProxyBlanket, '--elevated-caller <clsid> <request> <result>', '[abe] elevated decrypt failed', 'ERR:blanket'
> 
> **Source**: `ev-000006` · `ref:2909583825`

### 4. Collects wallet and desktop data

`T1555` · Confidence **high** · Static

It searches desktop wallet files, browser-extension wallets, clipboard text, screen captures, registry hives (SAM/SYSTEM/SECURITY/SOFTWARE) and session/domain information, and packs them into a timestamped archive.

> **Evidence**: literals wallet-seed.txt/wallet.dat/keystore.json, clipboard.txt, screen.bmp, hives, '[host] hive ', '[*] harvest packed: '; methods HarvestDesktop/HarvestHives/HarvestExtensionsAsync
> 
> **Source**: `ev-000006` · `ref:2909583825`

### 5. Weakens antivirus and telemetry

`T1562.001` · Confidence **high** · Static

It locates AmsiScanBuffer in amsi.dll and EtwEventWrite in ntdll, changes memory protection and patches them, and uses PowerShell Add-MpPreference to add exclusions for winhst.exe and powershell.exe.

> **Evidence**: literals amsi.dll/AmsiScanBuffer/ntdll.dll/EtwEventWrite/VirtualProtect, 'Add-MpPreference -ExclusionPath', 'Add-MpPreference -ExclusionProcess', winhst.exe, powershell.exe
> 
> **Source**: `ev-000006` · `ref:d576f8eae2`

### 6. Writes autostart persistence

`T1547.001` · Confidence **high** · Static

It copies itself to an install directory and writes the current-user Run key with the value name dsync, with the command line carrying --persist=auto --boot; on the Linux side it also writes an XDG autostart .desktop entry.

> **Evidence**: literals 'Software\Microsoft\Windows\CurrentVersion\Run', '[persist] kept (', '--persist=auto --boot', '[Desktop Entry]', 'X-GNOME-Autostart-enabled=true'
> 
> **Source**: `ev-000006` · `ref:2909583825`

### 7. Exfiltrates with a pinned public key

`T1071.001` · Confidence **high** · Static

It submits collection packages over HTTPS to /account and /dashboard on the configured host (default 196[.]251[.]102[.]202); before connecting it verifies the server with a built-in RSA-3072 public key, tries DGA-generated domains if verification fails, and stages offline if that also fails.

> **Evidence**: UTF-16 literals ' hxxps://', '/account', '/dashboard', 'BEGIN PUBLIC KEY', '[!] server closed the link without proving the pinned key', '[dga] ', '[!] pin failure ', and the Base64 public key following the IP 'MIIBojANBgkqhkiG9w0BAQEFAAOCAY8A...'
> 
> **Source**: `ev-000006` · `ref:2909583825`

### 8. Drops and retrieves follow-on payloads

`T1105` · Confidence **high** · Static

It pulls a drop payload from the server (with optional SHA-256 verification), writes it to a temporary payload_<timestamp> and starts it, and logs drop.log, acknowledgements and failed retries.

> **Evidence**: literals '--drop', '--drop-sha256', '--drop-anyway', 'payload_', '[drop] running pid ', '[*] acked ', '[!] no ack for ', 'spool:keep '
> 
> **Source**: `ev-000006` · `ref:2909583825`

### 9. Self-deletion and decoy drops

`T1070.004` · Confidence **high** · Static

On exit it uses cmd.exe to run a ping delay and then del itself; it drops decoy records such as cookies.txt/passwords.txt/wallet-seed.txt into the collection directory to foil manual triage.

> **Evidence**: literals '/c ping -n 3 127.0.0[.]1 >nul & del /f /q "', 'junk:start', '[junk] decoy records written'
> 
> **Source**: `ev-000006`

### 10. Environment self-check, then delayed dwell

`T1497.001` · Confidence **high** · Dynamic

After startup it scores the virtualization/analysis environment and waits out a dwell period (including a sleep-skip check); if the score hits, collection aborts. In this run the process loaded the .NET payload and then stayed silently resident for about 3 minutes, spawning no child processes and making no outbound connections.

> **Evidence**: dynamic timeline: pid 4256 started at 02:34:07 and was still alive at both memory dumps at 02:34:14 and 02:34:25, continuing to the end of observation; only one process-creation event, no child processes; memory strings GuardPolicy/GuardProbe/'[guard] analysis environment, aborting'; '[guard] dwell ok (+'
> 
> **Source**: `ref:f80473fa52` · `ev-000006`

### 11. In-memory loading of the stealing module

`T1497.003` · Confidence **medium** · Dynamic

At runtime the process actually loaded and compiled the collection-related methods (HarvestBrowserAsync, HarvestProfileAsync, HarvestHives, SendGuardedAsync and others); the stealing logic reached ready state along with the main assembly, but did not enter the collection stage within the window.

> **Evidence**: process memory dump strings include HarvestBrowserAsync/HarvestProfileAsync/HarvestExtensionsAsync/HarvestHives/SendGuardedAsync/DSYNC_SERVER/DSYNC_PIN/nblx-v2; no collection artifacts or outbound connections within 3 minutes, consistent with dwell-first, work-later sequencing
> 
> **Source**: `ref:f80473fa52`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://196[.]251[.]102[.]202/account` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://196[.]251[.]102[.]202/dashboard` | 443 | panel | Static | ⏳ Not observed |
| dns | `DGA (seed 89c7e1a14d62660f9665696997d1921d7e93a99573067392, falls back to a fixed host on failure)` | - | c2 | Static | ⏳ Not observed |

### Host

**Mutex**

- `Global\mtx-<random suffix> (single-instance mutex)`

**Drop path**

- `%TEMP%\payload_<yyyyMMddHHmmss>`
- `%TEMP%\dsync_launch_*.log`
- `<install directory>\installed.marker`
- `<install directory>\.shadow`
- `%LOCALAPPDATA%\...\spool`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run (value name dsync, command line with --persist=auto --boot)`
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths (read and repair)`
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Features (reads TamperProtection)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `196[.]251[.]102[.]202` | Yes | Static |
| `c2_uri_account` | `/account` | No | Static |
| `c2_uri_dashboard` | `/dashboard` | No | Static |
| `c2_port` | `443 (TLS; port does not appear as a constant, inferred from the https prefix)` | No | Static |
| `tls_pin_public_key` | `RSA-3072 SubjectPublicKeyInfo, Base64 prefix MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAv/QI9rrFckC+...AgMBAAE=` | Yes | Static |
| `dga_seed` | `89c7e1a14d62660f9665696997d1921d7e93a99573067392` | No | Static |
| `protocol_tag` | `nblx-v2` | No | Static |
| `install_marker` | `installed.marker` | No | Static |
| `mutex_prefix` | `Global\mtx-` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not judge it as ransomware or a wiper: the sample has no file encryption, shadow-copy deletion or disk-destruction logic.
- Do not claim credentials were successfully exfiltrated: no network request or exfiltration session initiated by the sample was seen in this dynamic window.
- Do not claim Defender exclusions or autostart entries were written on the host: only the corresponding code paths and command strings exist, and runtime telemetry showed no registry/service changes.
- Do not simply classify it as a downloader: its main capability is local browser and wallet data theft; dropping/retrieving payloads is only a supporting flow.
- Do not take the forged "Device Sync" product information as the real vendor attribution.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. No C2 session was obtained: the sample made zero outbound connections within the dynamic window, and the C2 host/paths/public key were all statically recovered and need later re-verification in a more realistic environment.
2. At runtime only process loading and residency were seen; no browser collection, Defender exclusions or autostart writes were observed; the related conclusions are based on code and literals and are static judgments.
3. The install-directory root path, the mutex random suffix and the DGA domain suffix were not obtained statically or dynamically.
4. The trailing high-entropy data section (NtWES, 2333 bytes) is not referenced by any data directory and may be encrypted configuration/key material/additional payload; it was not decrypted.
5. The family naming is not corroborated by any vendor engine or public rule; it is based only on the sample's internal identifiers (Device Sync, nblx-v2, DSYNC_*).

## Evidence Index

<details>
<summary>Expand 7 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:2909583825` | Sample triage | Hash/section entropy/import surface/packing-signal triage |
| `ref:57bf27c1c3` | PE structure parsing | PE structure: 3 randomly named sections, entry RVA 0, no import table, COM Descriptor points to .NET metadata |
| `ev-000006` | String extraction | Extracted 1957 ASCII / 757 UTF-16LE strings, including browser paths, Defender exclusions, DGA/pinned public key and more |
| `ref:d576f8eae2` | unpack.antidebug | Static anti-debug/anti-analysis technique identification (2 items, low confidence) |
| `ref:f80473fa52` | Dynamic analysis platform | Real dynamic run: pid 4256 started, two memory dumps, no child processes, no sample requests in network monitoring, before/after telemetry comparison, rollback |
| `telemetry:494610ff` | Dynamic telemetry | Dynamic telemetry recorded: 118 process/file events from the monitoring component; 1 ETW short-lived process event; 26 tool/system noise entries filtered |
| `etw:494610ff:4256` | Process event monitoring | Short-lived process event: 494610ff80608b4f0ca922fb27a8e1a2cd9d896ee4ae03384cf405faf4a6e3fc.exe (pid 4256; MD5=3DAA8D07D773074BBEFFC31447ADB4EF,SHA256=494610FF80608B4F0CA922FB27A8E1A2CD9D896EE4AE03384CF405FAF4A6E3FC,IMPHASH=00000000000000000000000000000000) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
