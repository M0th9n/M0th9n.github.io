---
title: "Malware Analysis: Vidar (PE · exe · fdaf6f90)"
published: 2026-11-22
draft: false
description: "Malicious (medium confidence): Vidar · stealer · hard difficulty · dynamic sandbox + static decompilation"
tags: ["Vidar", "stealer", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-Vidar-fdaf6f90"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Vidar** (uncertain) · Confidence **Medium**
> 
> Aliases: Vidar Stealer
> 
> Strings decrypted at runtime by the sample's own code clearly point to information-stealing capability: browser/wallet/plugin/file grab statistics, Telegram Desktop\tdata and Discord data.sqlite, Steam DialogConfig.vdf, credential memory reads (NtReadVirtualMemory/NtOpenProcess), Dead Drop Resolver C2 parsing, multi-threaded packing and exfiltration, plus virtualization and security-software probes such as VBoxSF/vioscsi/vmhgfs.sys/vmx86.sys/VBoxControl.exe/Malwarebytes. In the dynamic sandbox the sample did run, with the main thread sitting in a window message loop and already having generated a decoy dialog titled Warning in memory, which is anti-analysis behavior; because it hit virtualization checks it did not enter the stealing and outbound-connection phase.

## Overview

| Item | Content |
|:--|:--|
| Family | **Vidar** · alias Vidar Stealer · _uncertain_ |
| Confidence | **Medium** |
| Behavior classes | stealer |
| Difficulty | hard |
| First seen | 2026-11-22 09:43:31 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/fdaf6f9082118673a53720161657c11a4025689886b634777dcba60463154261/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Show virus decoy popup</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Runtime string decryption</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Resident GUI message loop</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Detect virtualization</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Dynamic native API resolve</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `fdaf6f9082118673a53720161657c11a4025689886b634777dcba60463154261` |
| MD5 | _Not recorded_ |
| Size | 966,656 bytes (944.0 KB) |
| Type | PE · `exe` |

## Behavior Analysis

**12** behaviors in total, each backed by evidence; **9** are static and **3** were obtained dynamically.

### 1. Show Virus Decoy Popup

`T1497` · Confidence **High** · Dynamic

At runtime it decrypts in .data(0xDD340) the body 'This is a VIRUS!!!! Do you want to run the file?\n\nTo remove the window, you must CRYPT FILE!' and the title 'Warning'; the main thread then sits in the window/message loop, an anti-analysis decoy interface.

> **Evidence**: Memory image 0xDD340/0xDD388 (title Warning); main thread RIP in win32u.dll message dispatch, sample return addresses 0x1C006/0x676F0/0x6A306 on the stack
> 
> **Source**: `ref:c25e7d6f41` · `ref:fb3485eab4` · `ref:82b2eed3e8`

### 2. Runtime String Decryption

`T1027` · Confidence **High** · Dynamic

The sample decrypts built-in strings one by one with an XOR stream; this analysis obtained plaintext buffers directly from .data in running memory (decoy popup text, Warning, 35 Nt* API names, kernel32/ntdll/user32 module names), proving the decryption routine actually executed.

> **Evidence**: Decoy text at 0xDD340; 35 Nt* names within 760 bytes from 0xDD4B8; module name table at 0xDA510; corresponding decryption functions FUN_14db99a40 / FUN_14db99ac4 and key derivation FUN_14dba90fc
> 
> **Source**: `ref:c25e7d6f41` · `ref:740646dc46` · `ref:7eab447bfb`

### 3. Resident GUI Message Loop

`T1497` · Confidence **High** · Dynamic

The process runs in the WINDOWS_GUI subsystem; after creating a window the main thread blocks in win32u message calls while three other threads wait in ntdll; the dynamic window produced no child processes, file writes, registry writes or network requests.

> **Evidence**: Sandbox timeline pid 7028 with a single process birth; monitoring component reports no injection/no hollow; thread RIPs in win32u.dll / ntdll.dll; network monitoring shows no sample-originated connection
> 
> **Source**: `ref:5eb2388dcc` · `ref:52a35a602b` · `ref:ff841d9a8f`

### 4. Detect Virtualization Environment

`T1497.001` · Confidence **High** · Static

Built-in checks cover VirtualBox service/drivers (VBoxSF, vioscsi, VBoxControl.exe), virtualization platform drivers and shared folders (vmhgfs.sys, vmx86.sys), and security products such as Malwarebytes plus a cpu_brand check; on a match it switches to the decoy flow.

> **Evidence**: Decrypted strings '[cpu_brand] OK (unsupported)', 'SYSTEM\ControlSet001\Services\VBoxSF', 'SYSTEM\ControlSet001\Services\vioscsi', 'vmhgfs.sys', 'vmx86.sys', 'VBoxControl.exe', 'Malwarebytes'
> 
> **Source**: `ref:7eab447bfb` · `ref:7d8e657a67`

### 5. Dynamic Native API Resolution

`T1106` · Confidence **High** · Static

No import table; it resolves kernel32/ntdll/user32 functions via PEB traversal and name/hash lookup, and plainly lists 35 Nt* native APIs (including NtCreateFile, NtQueryDirectoryFile, NtOpenProcess, NtReadVirtualMemory, NtCreateThreadEx and others).

> **Evidence**: 35 Nt* API names at runtime .data 0xDD4B8; module name table at 0xDA510; entry at 0x678BC reads gs:[0x60] PEB and resolves exports; GetProcAddress/LoadLibraryA name tables at .rdata 0x9BA28
> 
> **Source**: `ref:740646dc46` · `ref:77e40518e3` · `ref:768b1c2877`

### 6. Read Process-Memory Credentials

`T1555` · Confidence **Medium** · Static

The code contains the NtOpenProcess + NtReadVirtualMemory + NtQueryInformationProcess combination and the message '[keys] NtReadVirtualMemory not found', used to read credentials/keys from browser and other process memory.

> **Evidence**: Decrypted strings ' [keys] NtReadVirtualMemory not found', 'NtQueryInformationProcess'; NtReadVirtualMemory/NtOpenProcess/NtQueryVirtualMemory in the 0xDD4B8 API table
> 
> **Source**: `ref:7eab447bfb` · `ref:7d8e657a67` · `ref:740646dc46`

### 7. Collect Browsers and Wallets

`T1555.003` · Confidence **High** · Static

Collects data by browsers / wallets / plugins / soft / grabber categories and locates Chromium plugins, Firefox cert9.db and extension/wallet directories under Program Files (x86).

> **Evidence**: ' browsers: %d (%d rules), wallets: %d (%d rules), plugins: %d (%d wallet / %d plugins / %d soft), grabber: %d', 'Chromium Plugins', 'cert9.db', ' exe: %s (program files x86)'
> 
> **Source**: `ref:7eab447bfb` · `ref:f3e614f08c`

### 8. Steal IM Session Data

`T1539` · Confidence **High** · Static

Targets session/token files of Telegram Desktop tdata, Discord leveldb (storage\default\https+++discord[.]com\ls\data.sqlite) and Steam DialogConfig.vdf, and contains a JWT prefix constant (eyAidHlwIjogIkpXVC).

> **Evidence**: 'Telegram Desktop\tdata', 'storage\default\https+++discord[.]com\ls\data.sqlite', ' [discord] Firefox: %s — %d токен', 'DialogConfig.vdf', 'eyAidHlwIjogIkpXVC'
> 
> **Source**: `ref:7eab447bfb` · `ref:f3e614f08c`

### 9. Dead Drop Resolver C2

`T1102` · Confidence **Medium** · Static

Contains logic to fetch configuration/C2 via legitimate-service Dead Drop Resolver and derives encrypted domains as 'ENC domain'; this run did not reach that stage because of virtualization checks, so no network requests were produced.

> **Evidence**: Decrypted strings 'Dead drop: %s (sw: %s)', 'ENC domain: key derivation failed'; no pid 7028 connection in network monitoring logs
> 
> **Source**: `ref:7eab447bfb` · `ref:ff841d9a8f`

### 10. Multi-Threaded Packing and Exfiltration

`T1041` · Confidence **Medium** · Static

Stealing results are processed concurrently by a thread pool and reported as 'Sending %lu files in %d threads', with scheduling and mutex logic such as ' pool: %d threads' and 'Mutex acquired on attempt %d/%d'.

> **Evidence**: 'Sending %lu files in %d threads', ' pool: %d threads', 'Mutex acquired on attempt %d/%d' (all in the .rdata encrypted area, decrypted with the runtime key)
> 
> **Source**: `ref:7eab447bfb` · `ref:7d8e657a67`

### 11. Control-Flow Flattening Obfuscation

`T1027` · Confidence **High** · Static

Entry 0x678BC is a control-flow-flattened function with 512 basic blocks, paired with a 256-entry VM dispatch table and 0x243 bytes of virtual-machine bytecode (decrypted at runtime into .data 0xD9650); this VM also derives the string-decryption key.

> **Evidence**: 512 basic blocks in the entry CFG; decompiled FUN_14dba9160 is a byte-table VM interpreter; runtime .data 0xD9630=32-byte key, 0xD9650=0x243-byte VM bytecode (all zeros in the file)
> 
> **Source**: `ref:adee7dcb3a` · `ref:7265ac67f1` · `ref:5bf66d64b6`

### 12. Anti-Debugging and Environment Probing

`T1622` · Confidence **High** · Static

The code contains rdtsc timing deltas, int 2Dh, PEB(gs:[0x60]) access and cpuid probes for anti-debugging/anti-VM.

> **Evidence**: unpack.antidebug: rdtsc @ rva 0x1018, int 2Dh @ rva 0x75FE7, PEB gs:[0x60] @ rva 0x8766, cpuid @ rva 0x20D7
> 
> **Source**: `ref:f115de0b50` · `ref:768b1c2877`


## IOC (Defanged)

### Network

:::note
**No C2 / network IOC recovered** (see "Analysis Method and Limitations" at the end).
:::

### Host

**Drop paths**

- `%APPDATA%`
- `%APPDATA%\storage\default\https+++discord[.]com\ls\data.sqlite`
- `Telegram Desktop\tdata`
- `DialogConfig.vdf`
- `cert9.db`

**Registry**

- `SYSTEM\ControlSet001\Services\VBoxSF`
- `SYSTEM\ControlSet001\Services\vioscsi`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `string_encryption` | `Custom XOR stream: 32-byte key at .data(0xD9630, derived at runtime from 0x243-byte VM bytecode) + 32-bit rotating key selected by PEB state (file offsets 0x88878/0x8887C branches)` | Yes | static |
| `dead_drop_resolver` | `Dead Drop Resolver logic present ('Dead drop: %s (sw: %s)', 'ENC domain: key derivation failed'); the actual address is in an undecrypted 19,712-byte high-entropy block and was not recovered` | Yes | static |
| `c2_hosts` | `-` | No | static |
| `steal_targets` | `browsers / wallets / plugins / soft / grabber; Telegram tdata, Discord leveldb, Steam DialogConfig.vdf, Firefox cert9.db` | Yes | static |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not assert that data theft or exfiltration was completed in this run: no file reads/drops, child processes or sample-originated network connections were observed in the dynamic window, and the sample switched to the decoy popup and message loop after its built-in virtualization checks.
- Do not classify the sample as ransomware: 'you must CRYPT FILE' is only decoy popup copy, and no file encryption, extension changes or ransom-note drops were observed.
- Do not treat C2 addresses, mutex names or a family-unique identifier as confirmed: the dead-drop/domain configuration lies in an undecrypted 19,712-byte high-entropy block, so the family can only be given as a candidate.
- Do not claim that the corresponding operations actually occurred merely because symbols (NtReadVirtualMemory etc.) appear; these names come from the sample's decrypted string table and fixed API table.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacked | No |

**Limitations and pending verification**

1. In the sandbox the sample hit virtualization/anti-analysis checks and only displayed a decoy dialog and stayed in the message loop; no stealing, dropping, injection or outbound traffic was observed, so the actual theft scope and target list cannot be confirmed.
2. The dead-drop/encrypted-domain configuration lies in a 19,712-byte high-entropy block starting at .data 0xE18C0 (not decrypted at runtime), so c2 is empty and the C2/panel/mutex names were not recovered.
3. String decryption was recovered statically: the XOR stream was reproduced with the 32-byte derived key (0xD9630) in running memory and the dword rotating key selected by PEB state; this is a statically reproducible result, not cross-validated with outbound behavior.
4. The family name is a candidate (Vidar-like DDR stealer) without vendor naming, signature or self-name corroboration and needs external intelligence review.
5. Some Nt* APIs appear only in the decrypted string table and were not proven to be called one by one (for example the injection-related NtCreateThreadEx).
6. Sandbox telemetry recorded no registry writes or service creation by the sample process; keys such as VBoxSF/vioscsi are read probes, not writes.

## Evidence Index

<details>
<summary>Expand 16 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:662c2dcba5` | Sample triage | Hash/entropy/import-surface triage: 966,656 bytes, 0 imports, .text entropy 6.627, packing likelihood 0.25 |
| `ref:adb8d78aba` | PE structure parse | x64 GUI PE, entry RVA 0x678BC, no import/export/resource/debug directories, 5 standard sections |
| `ref:4b98f80721` | Import table parse | Import table empty (0 DLL / 0 symbols), consistent with dynamic resolution traits |
| `ref:f115de0b50` | unpack.antidebug | rdtsc / int 2Dh / PEB gs:[0x60] / cpuid anti-debug features |
| `ref:5eb2388dcc` | Dynamic analysis platform | win10 dynamic sandbox revert-detonate-poll: pid 7028 born, monitoring component/hollows show no injection, then reverted |
| `ref:52a35a602b` | Dynamic analysis platform | Timeline: only 1 candidate process, 6 minidumps, no child-process events |
| `ref:ff841d9a8f` | Dynamic artifact collection | Network monitoring log shows only system/Edge/OneDrive baseline traffic, no sample connection |
| `ref:c25e7d6f41` | script | Running-memory .data diff extraction: 0xDD340 decoy popup text+Warning, 35 Nt* API names from 0xDD4B8, 32-byte derived key at 0xD9630 |
| `ref:740646dc46` | script | Prints the 35 runtime-decrypted Nt* API names and decoy dialog text |
| `ref:7eab447bfb` | script | Reproduces XOR string decryption with the runtime key, recovering 31 stealer strings in .rdata (browsers/wallets/Dead drop/Discord/Telegram/Steam/VM checks etc.) |
| `ref:f2bf743b9b` | decompile.function | Decompiles FUN_14db6bcec on the entry chain: opens its own file, reads the header, locates data by tick value, finally MessageBox-displays the decrypted copy |
| `ref:7265ac67f1` | decompile.function | FUN_14dba9160 is a 256-entry dispatch-table bytecode VM interpreter |
| `ref:5bf66d64b6` | script | .data 0xD9630/0xD9650 are zero in the file and filled in running memory with the key and 0x243-byte VM bytecode |
| `ref:adee7dcb3a` | cfg.function | Entry function 0x678BC shows a 512-basic-block control-flow-flattened structure |
| `telemetry:fdaf6f90` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component 115 process/file events; 1 ETW short-lived process event; 22 tool/system noise events filtered |
| `etw:fdaf6f90:7028` | Process event monitoring | Short-lived process event: fdaf6f9082118673a53720161657c11a4025689886b634777dcba60463154261.exe (pid 7028; MD5=54C31DC6C25CA6B47A78C366F81478E8,SHA256=FDAF6F9082118673A53720161657C11A4025689886B634777DCBA60463154261,IMPHASH=00000000000000000000000000000000) |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
