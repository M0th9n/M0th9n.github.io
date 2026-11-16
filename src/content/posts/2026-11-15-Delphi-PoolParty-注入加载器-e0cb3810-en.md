---
title: "Malware Analysis: Delphi PoolParty Injector Loader (PE · exe · e0cb3810)"
published: 2026-11-15
draft: false
description: "Malicious (low confidence): Delphi PoolParty injector loader · loader/injector/pua_bundler · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Delphi PoolParty", "loader", "injector", "pua", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-15-Delphi-PoolParty-注入加载器-e0cb3810"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Delphi PoolParty injector loader** (uncertain) · Confidence **Low**
> 
> Aliases: TestPrivilegeAndHandle.dll, framework_PoolInjectLib, PoolPartyBof
> 
> The sample is a 64-bit Windows program whose main body was rewritten with control-flow flattening and hash-immediate dispatch, making static recovery difficult; its .data section hides a complete 64-bit Delphi injection module XORed with the single byte 0xDF. At runtime the sample manually maps that module inside its own process (base 0x1BCFE400000, 0x1AB000 bytes, MEM_PRIVATE, RWX, and absent from the loaded-module list), then spawns a child process with the same path. The payload module has SeDebugPrivilege elevation, ntdll user-mode hook removal, service/process enumeration, thread-pool (PoolParty) injection and self-deletion capabilities, and forges version information; the file also bundles an MD5 renumbering tool. Overall it is judged a malicious loader/injector.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Delphi PoolParty injector loader** · aliases TestPrivilegeAndHandle.dll, framework_PoolInjectLib, PoolPartyBof · _uncertain_ |
| Confidence | **Low** |
| Behavior class | loader · injector · pua_bundler |
| Difficulty | hard |
| First seen | 2026-11-14 16:27:57 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Control-flow flattening</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">XOR-hidden 64-bit payload</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reflective-load embedded DLL</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Thread-pool injection</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Enable debug privilege</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1134</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf` |
| MD5 | _not recorded_ |
| Size | 3,111,360 bytes (3.0 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**11** behaviors in total, each backed by evidence; **9** are statically available and **2** were obtained through dynamic analysis.

### 1. Control-flow flattening obfuscation

`T1027` · Confidence **High** · Static

The entry point and main logic were rewritten with control-flow flattening: a state variable and hash immediates (such as 0x8B430A26, 0xD25ABD30, 0x9D7EEADA) dispatch through a jump table, and decompilation results in a state-machine loop, indicating compile-time obfuscation.

> **Evidence**: From 0x14000F950, mov dword ptr [rdi],0x8B430A26; at 0x14000FB60, cmp/jg + jmp-table dispatch; decompilation presents a state machine
> 
> **Source**: `call:call_75f282465dfd47d790215267` · `ev-000014`

### 2. XOR-hidden 64-bit payload

`T1027.002` · Confidence **High** · Static

The .data section (RVA 0x2A000, 1,758,208 bytes) is entirely XORed with the single byte 0xDF and can be restored to a complete 64-bit PE (10 sections); its section sizes match the injection module that appears in runtime memory, and its strings include TestPrivilegeAndHandle and MyTimerUnit.

> **Evidence**: RVA 0x2A000 starts with bytes 92 85 9A 8D 37…, which after XOR 0xDF become a PE starting with MZER and e_lfanew=0x100
> 
> **Source**: `ev-000019` · `ev-000003` · `call:call_be6542bb63a24dc8b40d35bd`

### 3. Reflective loading of embedded DLL

`T1620` · Confidence **High** · Dynamic

At runtime it manually maps the decrypted 64-bit Delphi DLL inside its own process: memory module base 0x1BCFE400000, size 0x1AB000, MEM_PRIVATE, PAGE_EXECUTE_READWRITE, and absent from the loaded-module list; memory forensics classifies it as an implanted PE.

> **Evidence**: Process memory scan: module 1bcfe400000, module_size=1ab000, mapping_type=MEM_PRIVATE, protection=40, is_listed_module=0, implanted_pe=1
> 
> **Source**: `call:call_6a1de654b66f42d3b49daa46` · `call:call_be6542bb63a24dc8b40d35bd`

### 4. Thread-pool injection framework

`T1055` · Confidence **Medium** · Static

The payload DLL retains the strings framework_PoolInjectLib and PoolPartyBof and implements process-write injection primitives (WriteProcessMemory, VirtualAllocEx, NtWriteVirtualMemory, NtOpenProcess, etc.), providing PoolParty thread-pool injection capability; no actual injection into other processes was observed in this run.

> **Evidence**: Payload RVA 0x149F79 holds framework_PoolInjectLib, 0x149F91 holds PoolPartyBof; the import table includes WriteProcessMemory/VirtualAllocEx/NtWriteVirtualMemory
> 
> **Source**: `call:call_be6542bb63a24dc8b40d35bd` · `call:call_f72b7c794dc94316b585cd42` · `ev-000019`

### 5. Enable debug privilege for elevation

`T1134` · Confidence **Medium** · Static

The payload DLL implements EnableDebugPrivilege, GetAdmin and RunAsAdmin, opening SeDebugPrivilege through OpenProcessToken, LookupPrivilegeValue and AdjustTokenPrivileges, and prepares to restart itself as administrator.

> **Evidence**: RTTI methods EnableDebugPrivilege@0x13E282, RunAsAdmin@0x13E21F; imports AdjustTokenPrivileges/LookupPrivilegeValue/OpenProcessToken
> 
> **Source**: `call:call_be6542bb63a24dc8b40d35bd` · `call:call_f72b7c794dc94316b585cd42`

### 6. Remove ntdll user-mode hooks

`T1562.001` · Confidence **Medium** · Static

The payload DLL provides an UnHookNTdll method and references Winapi.Windows.PkgHelper, used to restore ntdll functions hooked by security products to evade monitoring.

> **Evidence**: RTTI method UnHookNTdll@0x13E0BD; unit Winapi.Windows.PkgHelper@0x14A017
> 
> **Source**: `call:call_be6542bb63a24dc8b40d35bd` · `ev-000019`

### 7. Enumerate services and processes

`T1057` · Confidence **Medium** · Static

The payload DLL implements ServiceToPID, GetProcessID and getPid, and imports OpenSCManager/StartService, Process32First/Process32Next and NtQuerySystemInformation, used to enumerate services and processes and pick targets.

> **Evidence**: RTTI ServiceToPID@0x13E12A; imports OpenSCManager/StartService/Process32FirstW/NtQuerySystemInformation
> 
> **Source**: `call:call_f72b7c794dc94316b585cd42` · `call:call_be6542bb63a24dc8b40d35bd`

### 8. Spawn a copy of itself

`T1548.002` · Confidence **Medium** · Dynamic

After completing injection, the main process (PID 8076) creates a child process (PID 7200) pointing at the same file, with the same command line as its parent; combined with the RunAsAdmin logic in the payload, this is judged an elevation-restart path. The child then crashes and triggers a system error report.

> **Evidence**: ETW process events: PID 7200, same Image path, ParentPID 8076; a WerFault process appears afterwards
> 
> **Source**: `call:call_6a1de654b66f42d3b49daa46`

### 9. Forged version information

`T1036.005` · Confidence **High** · Static

The version resource is forged with a random product name KeTTwXaSBnJ, company OHUuoKlBet and version 5.7.4344.928; the runtime process properties FileVersion/Description/Company/OriginalFilename match these forged values and do not correspond to the file's actual components.

> **Evidence**: VS_VERSION_INFO at 0x2F5F12: KeTTwXaSBnJ / 5.7.4344.928 / OHUuoKlBet; dynamic process properties show the same values
> 
> **Source**: `ev-000020` · `call:call_6a1de654b66f42d3b49daa46` · `ev-000018`

### 10. Bundled hash-renumbering tool

`T1027` · Confidence **High** · Static

In .rsrc, resource type EXE and resource name MD5EDITTOOLS bundle a complete 32-bit GUI program "MD5 Edit Tools 3.0.2[.]11" (author MagicDevil.Zhang@qq[.]com), containing doschangmd5.bat and a promotion-page URL, which is a hash-tampering/promotion PUP; it was not observed being dropped or executed in this run.

> **Evidence**: Resource EXE/MD5EDITTOOLS data RVA 0x1DF10C, size 0x11C000, i.e. the 32-bit PE at file offset 0x1D9F0C; version string MD5 Edit Tools 3.0.2[.]11
> 
> **Source**: `ev-000020` · `call:call_8afc542b978a429a8b821e40` · `ev-000015`

### 11. Self-deletion module

`T1070.004` · Confidence **Medium** · Static

The payload DLL implements a DeleteSelf method and imports DeleteFile/MoveFile, providing the ability to delete its own file after running; no deletion was observed in this run.

> **Evidence**: RTTI method DeleteSelf@0x13E0F4; imports DeleteFile/MoveFile
> 
> **Source**: `call:call_be6542bb63a24dc8b40d35bd` · `call:call_f72b7c794dc94316b585cd42`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://dn-magicdevil[.]qbox[.]me/md530211[.]html` | 80 | download | Static | ⏳ Not observed |
| http | `hxxp://dn-magicdevil[.]qbox[.]me/Ad[.]html` | 80 | download | Static | ⏳ Not observed |

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `embedded_payload` | `TestPrivilegeAndHandle.dll (64-bit Delphi PE, 0x1AB000 bytes after memory mapping)` | Yes | Static |
| `payload_xor_byte` | `0xDF (entire .data XOR, reliably restores the complete PE)` | Yes | Static |
| `injection_framework` | `framework_PoolInjectLib / PoolPartyBof (thread-pool worker-factory injection)` | No | Static |
| `bundled_tool` | `MD5 Edit Tools 3.0.2[.]11 (resource type EXE, name MD5EDITTOOLS, 32-bit Delphi GUI)` | No | Static |
| `fake_version_info` | `ProductName/OriginalFilename=KeTTwXaSBnJ, CompanyName=OHUuoKlBet, FileVersion=5.7.4344.928` | No | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not treat the bundled 32-bit MD5 Edit Tools as the loader itself, and do not claim it executed or landed on this host.
- This analysis obtained no C2 request/response or outbound session; do not claim the sample communicated with an external server or exfiltrated data.
- No file encryption, credential reads, registry Run-key writes, service creation or scheduled-task writes were observed; do not conclude it is ransomware, a stealer, or already persistent.
- The PoolParty/injection imports in the payload prove capability only; no actual injection into other processes was observed, so do not claim cross-process injection was completed.
- Family attribution lacks YARA, multi-engine or configuration-identifier support; do not assert it is a specific known APT/malware family.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `6dea8fa5bb340e838c5e91fea8a806ace9a889e6889b5e9ad6df4502749f4088`) |

**Limitations and pending verification**

1. No C2 address or complete configuration was obtained: neither static analysis nor runtime memory found a hardcoded host, and the configuration may depend on later instructions or external parameters.
2. No actual injection into other processes or lateral behavior was observed; the PoolParty/injection capability comes from payload strings and the import table, which is a capability judgment rather than observed behavior.
3. The child process crashes soon after launch (triggering a system error report), so whether the elevation restart follows the UAC path could not be fully confirmed.
4. The statically decrypted payload and the runtime memory dump differ by about 8% of bytes (base relocation, runtime patches), so a byte-for-byte comparison was not possible.
5. The bundled MD5 Edit Tools was neither dropped nor executed in this run; its network URLs are static strings only, and connectivity was not verified.
6. No actual writes related to registry, services, certificates or defense evasion were observed; those capability judgments all come from the payload import table and RTTI method names.

## Evidence Index

<details>
<summary>Expand 23 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf |
| `call:call_96c8cae628674032b35e97ac` | PE structure parsing | Outer 64-bit PE: 8 sections, .data 1.76MB, entry RVA 0x10B00, timestamp 0 |
| `call:call_b0af55f409de492e82fa5791` | Import table parsing | Outer layer imports only 74 KERNEL32 CRT/basic APIs (no network APIs), requiring dynamic resolution |
| `ev-000003` | scan.entropy | .data entropy 5.768 (1,758,208 bytes), suggesting large embedded data |
| `ev-000014` | decompile.ghidra | FUN_14000F950 decompiles to state-machine dispatch, confirming control-flow flattening and a byte-by-byte transform loop |
| `call:call_75f282465dfd47d790215267` | disasm.function | Instruction-level evidence from RVA 0xF950: hash immediate 0x8B430A26 and jmp-table dispatch |
| `ev-000019` | evidence.record | Script: .data XOR 0xDF restores the complete 64-bit PE (sha256=6dea8fa5…), ~92% match with the memory dump |
| `ev-000020` | evidence.record | Script: 32-bit MD5 Edit Tools at 0x1D9F0C and forged version information at 0x2F5F12 |
| `call:call_6a1de654b66f42d3b49daa46` | Dynamic analysis platform | Dynamic detonation: injected module 1bcfe400000 of PID 8076 was dumped; same-path child process PID 7200 spawned; no network egress |
| `call:call_be6542bb63a24dc8b40d35bd` | PE structure parsing | Injected module: 11 sections, entry RVA 0x1408B0, export table present, memory-dumped PE |
| `call:call_6ccfc09ba3aa472aba4a30df` | pe.exports | DLL name TestPrivilegeAndHandle.dll; exports dbkFCallWrapperAddr / __dbk_fcall_wrapper |
| `call:call_f72b7c794dc94316b585cd42` | pe.imports(dump) | Imports WriteProcessMemory/VirtualAllocEx/NtWriteVirtualMemory/AdjustTokenPrivileges/OpenSCManager and others |
| `call:call_8afc542b978a429a8b821e40` | PE structure parsing | Bundled 32-bit PE: 4 sections, entry RVA 0x8F37B, GUI subsystem |
| `ev-000015` | String extraction | Bundled tool strings: doschangmd5.bat, AutoAdd/Open/Net, C:..I: and others |
| `ev-000018` | String extraction | Outer long strings: PDB path C:\Users\Administrator\source\repos\ConsoleApplication3\x64\Release\ConsoleApplication3.pdb |
| `call:call_8493be7fc0ec48f4b416b243` | unpack.detect | No known packer signature (packed=false); obfuscation is compile-time control-flow flattening |
| `ev-000018` | String extraction | Long/encoded string check: readable strings concentrate in CRT and forged version information; key logic strings are carried by the XOR payload |
| `telemetry:e0cb3810` | Dynamic telemetry | Dynamic telemetry recorded: monitoring components registry events 1; monitoring components process/file events 145; ETW short-lived process events 6; filtered tool/system noise 29 |
| `etw:e0cb3810:8076` | Process event monitoring | Short-lived process event: e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf.exe (pid 8076; MD5=C1A4A7448BC3F868E624311621535CE1,SHA256=E0CB38109715476C5DB9BE2FC7FB4611B93E037467B0B3C56872537B623D5CCF,IMPHASH=C7F4A7C59999F7A98CFB176DEBD524C8) |
| `etw:e0cb3810:7200` | Process event monitoring | Short-lived process event: e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf.exe (pid 7200; MD5=C1A4A7448BC3F868E624311621535CE1,SHA256=E0CB38109715476C5DB9BE2FC7FB4611B93E037467B0B3C56872537B623D5CCF,IMPHASH=C7F4A7C59999F7A98CFB176DEBD524C8) |
| `etw:e0cb3810:7636` | Process event monitoring | Short-lived process event: ngentask.exe (pid 7636; MD5=3142937610966B092CA8886C76A3B113,SHA256=FF70C1B71440E34931EB8EF97236F3CB2BB2668C72E7A3338660CED5C0753AF8,IMPHASH=00000000000000000000000000000000) |
| `etw:e0cb3810:5100` | Process event monitoring | Short-lived process event: ngen.exe (pid 5100; MD5=B6C3FE33B436E5006514403824F17C66,SHA256=A446D35F5E60BDAE1A7117B71D90ABB0FEA424EE416B0E0ECD2C485DC5939A68,IMPHASH=4AD0B1CAB8B0F51517768C87B067BA8A) |
| `etw:e0cb3810:800` | Process event monitoring | Short-lived process event: ngen.exe (pid 800; MD5=B6C3FE33B436E5006514403824F17C66,SHA256=A446D35F5E60BDAE1A7117B71D90ABB0FEA424EE416B0E0ECD2C485DC5939A68,IMPHASH=4AD0B1CAB8B0F51517768C87B067BA8A) |

</details>

---

_This report's sample is not public, IOCs are defanged, and it is for security research only._
