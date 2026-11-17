---
title: "Malware Sample Analysis: ValleyRAT/Winos 4.0 Lineage Loader (Candidate) (PE · exe · 201f298a)"
published: 2026-11-17
draft: false
description: "Malicious (medium confidence): ValleyRAT/Winos 4.0 lineage loader (candidate) · loader/downloader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["ValleyRAT", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-ValleyRAT-Winos-4.0-系加载器-候选-201f298a"
---

> [!WARNING]
> **Verdict: malicious** · Family **ValleyRAT/Winos 4.0 lineage loader (candidate)** (doubtful) · Confidence **medium**
> 
> Aliases: Silver Fox, Winos 4.0, ValleyRAT loader
> 
> After actually running in an isolated Windows sandbox, within 1 minute the sample initiated TCP/443 to the Alibaba Cloud OSS address 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com and sent a complete HTTP request (GET /tad, User-Agent: 3M); this domain and request path do not exist in the on-disk file and appear only in process memory after execution, showing the configuration is decrypted/constructed at runtime; meanwhile its version resource and code signature both impersonate "Tencent Meeting 3.37.1[.]426 / Tencent Technology", and signature integrity verification returns a hash mismatch, i.e., a forged/stolen signature. Combined with the staging directory C:\Users\Public\pinIhy\ and the in-memory configuration such as VUXkpL.exe, it is judged to be a malicious loader/downloader rather than a normal installer package.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **ValleyRAT/Winos 4.0 lineage loader (candidate)** · aliases Silver Fox, Winos 4.0, ValleyRAT loader · _doubtful_ |
| Confidence | **Medium** |
| Behavior class | loader · downloader |
| Difficulty | hard |
| First seen | 2026-11-14 18:07:15 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/201f298ad9e5940aff96ac3a165c4a4800b50cc070b945e68d98dc9b28e5831e/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Impersonates Tencent Meeting signature</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">40MB padding inflates file</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Runtime-decrypted download config</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Requests payload from OSS</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Custom protocol points to backup C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `201f298ad9e5940aff96ac3a165c4a4800b50cc070b945e68d98dc9b28e5831e` |
| MD5 | _not recorded_ |
| Size | 40,893,088 bytes (39.0 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**6** behaviors in total, each backed by evidence; **3** are obtainable statically and **3** were obtained through dynamic analysis.

### 1. Impersonating the Tencent Meeting signature

`T1036.001` · Confidence **high** · Static

The version resource declares FileDescription/ProductName as "Tencent Meeting", version 3.37.1[.]426, copyright Tencent Corporation; the code signer in the certificate table is Tencent Technology (Shenzhen) Company Limited (issued by DigiCert, timestamp 2025-08-25), but integrity verification returns a hash mismatch, i.e., the file content does not match the hash signed at signing time and the signature was reused/forged.

> **Evidence**: version resource /16/1/2052 @RVA 0x2702548 contains "Tencent Meeting 3.37.1[.]426"; certificate table @RVA 0x26FB0E0; signature verification result HashMismatch
> 
> **Source**: `ref:e20b790a5b` · `ref:b4f488552d` · `ref:82d622c69f`

### 2. 40MB padding inflates the file

`T1027` · Confidence **high** · Static

The .data section has a raw size of 40,552,448 bytes (about 99% of the whole file) with entropy only 2.027; inside are large zero-padding areas and string/structure fragments from multiple unrelated programs (RPCS3, shadPS4, Terraform Provider, Tencent Meeting, Wondershare, etc.), and the same batch of strings repeats at multiple offsets with no evidence of being referenced by this program's code, consistent with the practice of "padding with unrelated data to push the size above thresholds and evade scanning".

> **Evidence**: .data starts at RVA 0x2F000, raw 40,552,448 bytes, entropy 2.027; 6.8MB mixed content from 0x1909B87; rsx_debugger repeats at 0xBA15B/0x19AF91B/0x1BE0CEB/0x26AE1BB
> 
> **Source**: `ref:f97acae034` · `ref:09dc82270f` · `ref:72bdd8bb2f` · `ref:1db6cfcb34`

### 3. Runtime-decrypted download configuration

`T1140` · Confidence **high** · Dynamic

After the process runs, plaintext configuration appears in memory: hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad, C:\Users\Public\pinIhy\ and C:\Users\Public\pinIhy\VUXkpL.exe; these complete strings cannot be found in the on-disk file (only the fragment "3spp0a" remains at the start of .text), showing the configuration is obtained by runtime decryption/concatenation.

> **Evidence**: hit count in the static file for 3byy0j/aliyuncs//tad/VUXkpL is 0; the memory image has hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad from offset 0x3E59C, and C:\Users\Public\pinIhy\VUXkpL.exe at 0x41674
> 
> **Source**: `ref:918d2c95b6` · `ref:fdc4042949` · `ref:eeb058802f`

### 4. Requesting the payload from OSS

`T1105` · Confidence **high** · Dynamic

About 1 minute after actual execution, the sample process initiated a TCP connection to 192.0.2[.]123:443 and sent a complete plaintext HTTP request: GET /tad HTTP/1.1, Host: 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com, User-Agent: 3M, Cache-Control: no-cache; i.e., it accessed port 443 over HTTP (not TLS) to request next-stage content from a third-party object storage.

> **Evidence**: network log 01:37:03 sample process (2244) requested TCP :443; 01:37:05 HTTPListener443 recorded GET /tad, Host=3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com, UA=3M
> 
> **Source**: `ref:efd8a77229` · `ref:bebdb83e9d`

### 5. Custom protocol pointing to a backup C2

`T1071` · Confidence **medium** · Static

The in-memory configuration contains a custom-protocol address ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/ (random second-level domain + unusual TLD .tfd), stored alongside the OSS download address as a backup control/callback entry independent of the HTTP download channel; the on-disk static file retains only its fragment "3spp0a".

> **Evidence**: "ykkgj://" at memory 0x3E8CC, "ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/" at 0x3EBDC; fragment "3spp0a" at static file offset 0x42B
> 
> **Source**: `ref:fdc4042949` · `ref:37f21e67b3`

### 6. Staging the payload in the public directory

`T1074` · Confidence **high** · Dynamic

The configuration consistently uses %PUBLIC%\pinIhy\ as the staging directory and gives the drop filename VUXkpL.exe; this directory is under the Public path writable by all users, facilitating unprivileged writes and loading by subsequent processes — a typical preparation step for download-then-execute (no actual file write event was captured within this analysis window).

> **Evidence**: memory offsets 0x3E40C / 0x3E6AC / 0x3F7FC are all C:\Users\Public\pinIhy\; 0x41674 is ...\VUXkpL.exe
> 
> **Source**: `ref:fdc4042949`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**The real server side remains unverified**: the above connection/handshake was completed with a locally controlled emulation service; the real C2's response and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad` | 443 | download | Dynamic | Observed |
| other | `ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/` | - | c2 | Static | ⏳ Not observed |

### Host

**Drop paths**

- `C:\Users\Public\pinIhy\`
- `C:\Users\Public\pinIhy\VUXkpL.exe`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `payload_url` | `hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad` | Yes | Dynamic |
| `user_agent` | `3M` | Yes | Dynamic |
| `staging_dir` | `%PUBLIC%\pinIhy\` | Yes | Dynamic |
| `dropped_payload_path` | `%PUBLIC%\pinIhy\VUXkpL.exe` | No | Dynamic |
| `c2_hosts` | `3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd (protocol prefix ykkgj://)` | No | Static |
| `protocol_scheme` | `ykkgj://` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; note this when citing this report.

- Do not conclude that the sample bundles these programs or has emulator/cloud-migration functionality just because strings such as RPCS3, shadPS4, Terraform Provider, Tencent Meeting appear in the file — this content is in the unreachable 40MB padding region and no reference by this program's code was seen.
- Do not claim persistence behavior was observed (scheduled tasks, Run keys, service installation): there were no registry/service/task events within the dynamic window; the CurrentVersion\Run string in memory comes from system modules, not the sample itself.
- Do not claim the second-stage payload was downloaded and executed: only one HTTP GET request and the in-memory drop path strings were captured; no response body, file write, or new process was seen.
- Do not describe ykkgj:// as a verified usable C2 channel: it comes only from an in-memory configuration string, and no send/receive interaction was observed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. Within the dynamic observation window, no response body or dropped file was captured, so the second-stage payload type and actual execution result cannot be confirmed.
2. Most of the 40.5MB in .data consists of mutually unrelated program string fragments; the static reference chain could not locate the code that decrypts/uses it; the .text body is the MSVC runtime library with an abnormal jump at the entry point, and the full decryption algorithm was not recovered.
3. The file's Authenticode verification returns a hash mismatch, so it cannot be determined whether tampering occurred before or after packaging.
4. The custom-protocol address ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/ comes only from an in-memory string; no availability verification was done and no actual callback was observed.
5. The sandbox did not collect file-system and registry telemetry; the drop directory and persistence can only be inferred from memory strings and cannot be considered to have occurred.

## Evidence Index

<details>
<summary>Expand 20 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:09dc82270f` | Sample triage | one-stop triage of hash/imphash/section entropy/anomalies/packing score; 40MB .data, entropy 2.027, packing.score=0, anomaly=0 |
| `ref:f97acae034` | PE structure parsing | PE64 GUI, entry RVA 0x98C0, 7 sections, .data raw 40,552,448 bytes, characteristics include RELOCS_STRIPPED but .reloc exists |
| `ref:09ff19ec7c` | Import table parsing | 4 imported DLLs / 88 symbols, including ShellExecuteW, CoCreateInstance, VirtualAlloc, CreateFileW, FindFirstFileExW, IsDebuggerPresent |
| `ref:37f21e67b3` | String extraction | ASCII 33330 / UTF16 569; fragment 3spp0a appears at file offset 0x42B |
| `ref:05364e4e0e` | Cryptographic constant identification | hits AES S-box/inverse S-box, SHA-256, MD5, CRC32, base64 constants (all in the padding region) |
| `ref:e20b790a5b` | script | parse version resource /16/1/2052: Tencent Meeting 3.37.1[.]426 / © Tencent Corporation |
| `ref:b4f488552d` | script | certificate table strings: DigiCert chain + Tencent Technology (Shenzhen) Company Limited + 2025-08-25 timestamp |
| `ref:82d622c69f` | script | system signature verification: Status=HashMismatch, signer certificate subject is Tencent Technology (Shenzhen) |
| `ref:72bdd8bb2f` | script | padding region hits unrelated program strings such as rpcs3_app/rsx_debugger/shadPS4/sceAudioOutOpen |
| `ref:1db6cfcb34` | script | padding region hits Go module paths such as terraform-provider-vcd, vmware/go-vcloud-director |
| `ref:bebdb83e9d` | Dynamic analysis platform | sandbox detonation: 1 candidate process, no hollows, no targeted dumps, rolled back after wrap-up; timeline records sample PID and memory dump |
| `ref:efd8a77229` | script | network monitoring log: sample process requests TCP :443, then GET /tad appears, Host=3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com, UA=3M |
| `ref:eeb058802f` | script | process memory image search: 21-22 hits each for 3byy0j/aliyuncs, 5 hits for /tad (0 hits in the on-disk file) |
| `ref:fdc4042949` | script | in-memory configuration region recovery: hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad, C:\Users\Public\pinIhy\, VUXkpL.exe, ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/ |
| `ref:918d2c95b6` | script | static file search for 3byy0j/aliyuncs/oss-cn-beijing all 0 hits, proving the configuration is generated at runtime |
| `ref:6a20b14125` | unpack.detect | static packer detection no hit (packed=false), consistent with the "self-padding rather than encrypted packer" structure |
| `ref:15bb76986d` | disasm.function | entry RVA 0x98C0: calls __security_init_cookie then jumps to RVA 0x11EC, a non-standard CRT entry path |
| `c2_evidence:201f298a` | Connection evidence extraction | dynamic network monitoring recorded 1 connection attempt to 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com:443; full session not captured |
| `telemetry:201f298a` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 108; ETW short-lived process events 1; filtered tool/system noise 27 |
| `etw:201f298a:2244` | Process event monitoring | Short-lived process event: 201f298ad9e5940aff96ac3a165c4a4800b50cc070b945e68d98dc9b28e5831e.exe (pid 2244; MD5=401E4A3730E1932E6A77D52249850EFB,SHA256=201F298AD9E5940AFF96AC3A165C4A4800B50CC070B945E68D98DC9B28E5831E,IMPHASH=20ABBE0F6AB059EA4A375BCB6B8A717B) |

</details>

---

_This report's sample is not public; IOCs are defanged; for security research only._
