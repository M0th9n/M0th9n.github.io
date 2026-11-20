---
title: "Malware Sample Analysis: PineBorough Loader (PE · exe · 2075bc1b)"
published: 2026-11-19
draft: false
description: "Malicious (low confidence): PineBorough Loader · loader/injector · difficulty medium · dynamic sandbox + static decompilation"
tags: ["PineBorough", "loader", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-19-PineBorough-Loader-2075bc1b"
---

> [!WARNING]
> **Verdict: Malicious** · Family **PineBorough Loader** (doubtful) · Confidence **low**
> 
> Aliases: StartMenuPin, Start Menu Pin loader, Document Manager decoy
> 
> The sample hides a complete PE inside .rdata using 256-word vocabulary-index XOR followed by AES-256-CTR; at runtime it decrypts it through BCrypt and performs process-hollowing injection via NtCreateUserProcess/NtUnmapViewOfSection/NtAllocateVirtualMemory/NtWriteVirtualMemory/NtGetContextThread/NtSetContextThread/NtResumeThread. It also implements NtQueryInformationProcess anti-debugging, delay and memory/CPU environment checks, API-name XOR hiding and other evasion techniques, and masquerades as a legitimate desktop component. In the dynamic sandbox, bcrypt loading and a plaintext PE appearing in process memory were observed.

## Overview

| Item | Content |
|:--|:--|
| Family | **PineBorough Loader** · aliases StartMenuPin, Start Menu Pin loader, Document Manager decoy · _doubtful_ |
| Confidence | **low** |
| Behavior class | loader · injector |
| Difficulty | medium |
| First seen | 2026-11-17 18:33:15 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/2075bc1baa8fb95e5cdc559de8a7f1d400f74fe0a517b71833d5ad0eb506a39a/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Vocabulary-encoded payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">AES-CTR decrypts payload</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Dynamic API resolution</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Anti-debug probing</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Payload appears in memory</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Observed</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `2075bc1baa8fb95e5cdc559de8a7f1d400f74fe0a517b71833d5ad0eb506a39a` |
| MD5 | _not recorded_ |
| Size | 2,418,616 bytes (2.3 MB) |
| Type | PE · `exe` |

## Behavior Analysis

A total of **11** behaviors, each with attached evidence; **10** are statically available and **1** was obtained through dynamic analysis.

### 1. Vocabulary-Encoded Hidden Payload

`T1027` · Confidence **high** · Static

The roughly 2.1 MB of English word text in .rdata is not ordinary strings but a vocabulary encoding of 410640 tokens; at runtime each token is mapped to a 0-255 index that serves as a ciphertext byte of the payload.

> **Evidence**: 0x140001000 vocabulary hash table construction and token matching loop; PTR_DAT_1400086c0 256-word vocabulary; text block starting at .rdata RVA 0xADF0
> 
> **Source**: `ev-000013` · `ev-000018`

### 2. AES-CTR Payload Decryption

`T1140` · Confidence **high** · Static

The decoded ciphertext is then decrypted with BCrypt AES-256 in counter mode: a 32-byte derived key (each byte (i*7+0x59) XOR built-in table), a 12-byte nonce and a little-endian counter generate a keystream that is XORed, yielding a 410640-byte executable image.

> **Evidence**: 0x140001aa0 calls BCryptOpenAlgorithmProvider/SetProperty(ChainingModeECB)/GenerateSymmetricKey/BCryptEncrypt then XORs
> 
> **Source**: `ev-000015` · `ev-000018`

### 3. Dynamic API Resolution

`T1027` · Confidence **high** · Static

All sensitive API names are stored in .rdata obfuscated with 0x85 XOR; at startup each is decrypted in turn and resolved via GetProcAddress, so no sensitive ntdll/bcrypt functions are exposed in the import table.

> **Evidence**: 0x140001940 XORs 64-byte blocks and the final segment with 0x85 then calls GetProcAddress; resolves VirtualAlloc/NtCreateUserProcess/BCrypt* etc.
> 
> **Source**: `ev-000014` · `ev-000013` · `b97dd4db39`

### 4. Anti-Debug Probing

`T1622` · Confidence **high** · Static

Queries ProcessDebugPort(7) and ProcessDebugFlags(0x1e) separately via NtQueryInformationProcess; if a debugger is detected it calls ExitProcess and exits silently.

> **Evidence**: in 0x140001000, (*NtQueryInformationProcess)(handle,7,&buf,8) and (...,0x1e,&flags)
> 
> **Source**: `ev-000013`

### 5. Delay-Based Anti-Sandbox

`T1497.003` · Confidence **high** · Static

Records GetTickCount64, calls Sleep(2551ms) and reads the time again; if the actual interval is less than 2051ms it concludes time was accelerated/hooked and exits.

> **Evidence**: 0x140001000 GetTickCount64 -> Sleep(0x9f7) -> GetTickCount64, exits if the difference < 0x803
> 
> **Source**: `ev-000013`

### 6. Memory and CPU Checks

`T1497.001` · Confidence **high** · Static

Uses GlobalMemoryStatusEx to check whether physical memory exceeds 1.5 GB and GetSystemInfo to check the processor count, and calls GetUserNameA/RegOpenKeyExA/GDI/GetSystemMetrics etc. to collect environment characteristics used in conditional checks.

> **Evidence**: 0x140001000 GlobalMemoryStatusEx + GetSystemInfo(dwNumberOfProcessors); 0x1400035d0 collects username/registry/display environment
> 
> **Source**: `ev-000013` · `ev-000027`

### 7. Process Hollowing Injection

`T1055.012` · Confidence **high** · Static

Resolves whichever of svchost.exe/dllhost.exe/rundll32.exe/notepad.exe exists under System32; NtCreateUserProcess creates a suspended process, then it unmaps its image, allocates memory, writes the decrypted image, fixes relocations, rewrites RCX/RIP to the entry point and resumes execution with NtResumeThread.

> **Evidence**: 0x140002120 calls NtUnmapViewOfSection/NtAllocateVirtualMemory/NtWriteVirtualMemory/NtGetContextThread/NtSetContextThread/NtResumeThread in sequence; 0x140001e10 decrypts and concatenates paths such as \svchost.exe
> 
> **Source**: `ev-000016` · `ev-000031` · `7adb02f4be`

### 8. Masquerading as a Legitimate Program

`T1036.005` · Confidence **high** · Static

The version resource forges company PineBorough Park Utilities Ltd., product Start Menu Pin, description Background desktop service component and original filename StartMenuPin.exe, and it is covered by large blocks of office-software-style fake strings and fake log messages.

> **Evidence**: UTF-16 version information near resource section RVA 0x2511EC; Document Manager fake message table starting at 0x14000A7xx
> 
> **Source**: `4ad5b2fc75` · `194f498424` · `ev-000017`

### 9. Junk Code Padding

`T1027` · Confidence **high** · Static

Many functions that appear to have business meaning actually only perform side-effect-free operations such as length/CRC/base64 on fake configuration strings, raising static analysis cost and diluting the real control flow.

> **Evidence**: 0x140003230/0x140003470/0x140003790/0x140003080 only perform hash and length operations on Document Manager fake configuration strings
> 
> **Source**: `ev-000026` · `ev-000028` · `ev-000029`

### 10. Payload Appears in Memory

`T1140` · Confidence **high** · Dynamic

In the dynamic sandbox the sample loads bcrypt.dll; about 3 seconds after startup, a process memory dump shows a complete decrypted PE header at offset 0x33613F, proving the embedded payload has been restored in memory.

> **Evidence**: early.t0.dmp offset 0x33613F hits stage2 PE header (sha256 6e6acaa1...); monitoring component module list includes bcrypt.dll
> 
> **Source**: `7a79f120e5` · `2bf2d789d1`

### 11. Drops a Pure-GUI Decoy

`T1027` · Confidence **medium** · Static

The decrypted second stage is a PE32+ x64 GUI program (1215 functions); its imports are limited to kernel32 string/heap/thread, USER32, GDI32 and SHELL32, with no network, file, registry or process-manipulation APIs imported, and it exhibits no malicious capability on its own.

> **Evidence**: stage2 entry 0x140004290; import table has only 4 DLLs/76 symbols; no socket/WinHttp/CreateFile/RegSetValue imports
> 
> **Source**: `ev-000030` · `1e1b2b5484` · `ev-000019`


## IOC (Defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis Method and Limitations" at the end for the reason).
:::

### Host

**Drop Paths**

- `%SystemRoot%\System32\svchost.exe`
- `%SystemRoot%\System32\dllhost.exe`
- `%SystemRoot%\System32\rundll32.exe`
- `%SystemRoot%\System32\notepad.exe`

### Configuration

| Key | Value | Required | Evidence Source |
|:--|:--|:--|:--|
| `c2_hosts` | `-` | No | Static |
| `encryption_algo` | `AES-256-CTR (BCrypt: XOR after AES/ECB encrypting the counter block), 32-byte key, 12-byte nonce` | Yes | Static |
| `payload_encoding` | `256-word vocabulary: each token's vocabulary index as a single byte, then cyclically XORed with 81 A7 53 FB` | Yes | Static |
| `payload_size` | `410640` | Yes | Static |
| `hollow_targets` | `\svchost.exe;\dllhost.exe;\rundll32.exe;\notepad.exe (first one present under System32)` | Yes | Static |
| `install_path` | `-` | No | Static |
| `mutex` | `-` | No | Static |
| `campaign_id` | `-` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not call it ransomware or a file encryptor: no file traversal/encryption/deletion or ransom-note logic was found; AES is only used to protect the embedded payload.
- Do not call it an infostealer: there is no browser-credential, wallet or keylogging code, and no file/network data-exfiltration APIs are imported.
- Do not claim it has C2 or outbound connections: there are no network APIs, and the dynamic sandbox network log contains no requests or sessions related to this sample.
- Do not claim it achieves persistence: no registry Run key, service or scheduled-task writes were observed.
- Do not judge the sample as benign merely because the second stage is a GUI program: the loader's own hiding, anti-debugging and process-hollowing behavior already constitute malicious capability.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `6e6acaa1fcb21bd405d8a3befc09601d4107dfb51e8b96a3e3041f0c2c1bdab8`) |

**Limitations and Pending Verification**

1. The dynamic sandbox timeline contains only the sample's own process; no child processes such as svchost.exe/dllhost.exe appeared, and process hollowing was not observed in this environment (it may have failed to create or been affected by environment differences), so whether injection succeeded could not be dynamically confirmed.
2. The second stage is a GUI program importing only USER32/GDI32/SHELL32 plus string/heap/thread functions; neither static nor dynamic analysis shows network, file, registry or credential access, so its true purpose cannot be confirmed and it may be only a decoy or placeholder payload.
3. No C2 configuration, domain or IP could be extracted; there are no network APIs, and network monitoring captured no requests related to this sample.
4. A plaintext PE was confirmed in the memory dump, but the image written into the target process was not directly captured; the injection-chain evidence is mainly the static call chain.
5. Anti-debugging and timing/environment checks may cause early exit on different hardware or accelerated environments, so behavior may differ across sandboxes.

## Evidence Index

<details>
<summary>Expand 13 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprinting | Parent sample sha256/md5/sha1 |
| `ev-000002` | scan.imphash | imphash 416e71941f92841b6e99d0f352f195e6 |
| `ev-000011` | String extraction | Parent sample strings (including Word vocabulary, masqueraded version information) |
| `ev-000013` | decompile.ghidra | 0x140001000: anti-debug/timing/environment checks + vocabulary decoding + AES-CTR |
| `ev-000014` | decompile.ghidra | 0x140001940: XOR-decrypts export names then GetProcAddress |
| `ev-000015` | decompile.ghidra | 0x140001aa0: BCrypt AES-256-CTR decryption |
| `ev-000016` | decompile.ghidra | 0x140002120: NtCreateUserProcess process-hollowing injection |
| `ev-000018` | evidence.record | Script fully restores the second-stage PE and provides sha256 |
| `ev-000019` | String extraction | Second-stage strings (UI vocabulary only) |
| `ev-000030` | decompile.ghidra | Second-stage entry 0x140004290 |
| `ev-000031` | decompile.ghidra | 0x140001e10: decrypts and concatenates target paths such as \svchost.exe |
| `telemetry:2075bc1b` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 97; ETW short-lived process events 1; 27 filtered as tool/system noise |
| `etw:2075bc1b:1144` | Process event monitoring | Short-lived process event: 2075bc1baa8fb95e5cdc559de8a7f1d400f74fe0a517b71833d5ad0eb506a39a.exe (pid 1144; MD5=BAF7E87CCBF9F1085805C96793F24E90,SHA256=2075BC1BAA8FB95E5CDC559DE8A7F1D400F74FE0A517B71833D5AD0EB506A39A,IMPHASH=416E71941F92841B6E99D0F352F195E6) |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
