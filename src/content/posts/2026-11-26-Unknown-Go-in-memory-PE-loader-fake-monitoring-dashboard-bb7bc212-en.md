---
title: "Malware analysis: Unknown Go in-memory PE loader (fake monitoring dashboard) (PE · exe · bb7bc212)"
published: 2026-11-26
draft: false
description: "Malicious (low confidence): Unknown Go in-memory PE loader (fake monitoring dashboard) · loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-26-Unknown-Go-in-memory-PE-loader-fake-monitoring-dashboard-bb7bc212"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unknown Go in-memory PE loader (fake monitoring dashboard)** (uncertain) · Confidence **low**
> 
> This program is a console application compiled with Go 1.25.4 that on the surface loops printing a fictional "network infrastructure monitoring dashboard" (8 nodes, online/degraded/offline statistics, fictional bandwidth and reliability scores), but both static and runtime evidence point to a hidden payload: its .rdata contains an approximately 1.1 MB near-random high-entropy data block; during dynamic analysis, a complete 64-bit PE image (base 0x220000000, 0x25a000 bytes, 4 sections) not registered in the module list was found in MEM_PRIVATE, RWX (protection 0x40) memory of the sample's own process, and its rebuilt import table contains ntdll native memory/thread/process APIs and bcrypt cryptographic APIs. The entire process involves no child processes, no file drops and no outbound connections, matching the covert execution pattern of "disguised interface + in-memory payload loading/execution"; judged malicious.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Unknown Go in-memory PE loader (fake monitoring dashboard)** · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader |
| Difficulty | hard |
| First seen | 2026-11-25 11:04:51 |
| Analysis method | dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/bb7bc21269b543e669840e8771b6729ee254ccfe989115c0c8c6216175e7a0c1/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Map embedded PE into memory</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Payload imports native APIs</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Fake dashboard as cover</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Resolve APIs at runtime</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Embedded high-entropy payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `bb7bc21269b543e669840e8771b6729ee254ccfe989115c0c8c6216175e7a0c1` |
| MD5 | _not recorded_ |
| Size | 3,313,152 bytes (3.2 MB) |
| Type | PE · `exe` |

## Behavior analysis

**5** behaviors in total, each backed by evidence; **3** are available statically and **2** were obtained through dynamic analysis.

### 1. Map the embedded PE into memory

`T1620` · Confidence **high** · Dynamic

During execution, a complete PE image not registered in the loaded-module list appears inside the sample process: it resides in MEM_PRIVATE memory with RWX protection (0x40), is 0x25a000 in size and has 4 sections (.text about 1.1 MB, .data about 1.3 MB); the PE headers were recognized by the memory forensics tool and successfully dumped according to the image layout. No processes other than the sample itself were running, indicating the image was created by the sample process itself.

> **Evidence**: memory forensics report: scanned.modified.implanted_pe=1, implanted_shc=0; module=220000000, mapping_type=MEM_PRIVATE, protection=40, is_listed_module=0, sections_count=4; corresponding dump file 220000000.exe (2,468,642 bytes)
> 
> **Source**: `ref:3e56e28918` · `ref:8c7ec44593`

### 2. Payload imports native APIs

`T1106` · Confidence **high** · Dynamic

The import table rebuilt from the mapped PE module points to native system interfaces: ntdll's NtAllocateVirtualMemory / NtFreeVirtualMemory / NtProtectVirtualMemory / NtWriteVirtualMemory / NtReadVirtualMemory / NtCreateThreadEx / NtOpenProcess / NtTerminateProcess / NtQueryInformationProcess / NtSetInformationThread / NtQuerySystemInformation / NtCreateFile / NtQueryDirectoryFile / NtCreateMutant / NtCreateSemaphore etc., plus bcrypt's BCryptOpenAlgorithmProvider / BCryptGenerateSymmetricKey / BCryptEncrypt / BCryptDecrypt / BCryptGenRandom. Imports are concentrated in a few IAT blocks, one import per DLL, consistent with manual loading/memory-rebuilt imports.

> **Evidence**: memory dump rebuilt imports: bcrypt 8 items, kernel32/user32 9 items, ntdll 27 items (NtCreateThreadEx @ 0x233188, NtWriteVirtualMemory @ 0x2331c0, BCryptEncrypt @ 0x11b0b0, etc.)
> 
> **Source**: `ref:869b04e902` · `ref:8c7ec44593`

### 3. Fake monitoring dashboard as cover

`T1036` · Confidence **high** · Static

The main program loops outputting "NETWORK INFRASTRUCTURE MONITORING DASHBOARD / NETWORK HEALTH STATUS / DETAILED NODE REPORT" with fake data for a fixed set of 8 nodes, counts online/degraded/offline nodes and prints fictional bandwidth, packet loss, reliability scores, alerts and similar text, making the process look like an operations monitoring tool; this is interface disguise and attention cover for the malicious payload.

> **Evidence**: main.Cccntqygoqiewrjahjbr @0x1400e4300 repeatedly calls runtime.printstring to print the above titles, node table and percentages; the strings "Network Size: ", "Online Nodes: ", "Degraded Nodes: ", "Offline Nodes: ", "Network Health: " are located in the constant area near 0x140123a02
> 
> **Source**: `ref:381a2e761e` · `ref:01f4c5adc0`

### 4. Resolve APIs dynamically at runtime

`T1106` · Confidence **medium** · Static

The static import table contains only kernel32, but main.xcwal resolves a runtime lazy API via syscall.(*LazyProc).Find and immediately calls it once with syscall.SyscallN (gopanic on error); main.etmrhfknxqoan then calls the same lazy procedure via syscall.(*LazyProc).Call. This call path does not appear in the import table; it is runtime API resolution, commonly used to evade static import signatures.

> **Evidence**: main.xcwal +0x40: call 0x14007b880 (syscall.(*LazyProc).Find); +0x8f: call 0x14006c000 (syscall.SyscallN); main.etmrhfknxqoan +0x431: call 0x14007ba60 (syscall.(*LazyProc).Call)
> 
> **Source**: `ref:b83ccc5a04` · `ref:18c26ab11f` · `ref:89a767b436`

### 5. Embedded high-entropy payload data

`T1027.009` · Confidence **medium** · Static

The program's .rdata section has an overall entropy of 7.162, and within it file offsets 0x160000–0x274000 (about 1.1 MB) form a near-random data block with entropy 7.996–7.998, clearly distinct from the Go code and symbol areas; the program links no cryptographic or compression libraries, yet a complete PE image appears in runtime memory, indicating the high-entropy block is an encrypted/compressed payload container distributed with the program.

> **Evidence**: block entropy: each 64KB block in 0x170000–0x260000 has entropy 7.996–7.998; .rdata section entropy 7.162 (evidence ev-000004); linked package list is standard library only: bufio/io/os/sort/strings/syscall/time etc., no crypto/* or compress/*
> 
> **Source**: `ref:df1d768ab1` · `ref:47e7d910e0` · `ref:082e23804c`


## IOCs (defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis method and limitations" at the end of this report for the reason).
:::

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `payload_in_memory_base` | `0x220000000` | Yes | Dynamic |
| `payload_in_memory_size` | `0x25a000` | Yes | Dynamic |
| `payload_entry_rva` | `0xEA080` | No | Dynamic |
| `payload_sections` | `.text/.rdata/.data/.reloc (4)` | No | Dynamic |
| `c2_hosts` | `-` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; take care when citing this report.

- Do not assert that account creation, token theft or certificate operations were performed merely because API names such as NetUserAdd / LogonUserW / CreateProcessAsUserW / CertOpenStore appear in the string table — no corresponding call chains were found, and most of these are lazy API name constants from the Go standard library.
- Do not claim C2 communication or data exfiltration: no network connections from the sample were seen within the dynamic window, and network monitoring recorded only update/certificate-validation requests from system components.
- Do not claim persistence was implemented: no file writes, registry modifications, service or scheduled-task creation were observed.
- Do not treat the fake "network monitoring dashboard" as genuine IT-operations tool behavior or judge the sample benign on that basis.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | dynamic sandbox analysis + static decompilation |
| Unpacked | Yes (stage2 `ab62b4878f36565e83934044a5baf22dab6c694d604a0badf6185a7ee66612f1`) |

**Limitations and pending verification**

1. No C2 address, URI or encrypted configuration was obtained: no network session from the sample occurred within the dynamic window, so c2 is empty.
2. The entry-point logic of the mapped PE was not recovered: its string area holds only 269 short ASCII strings without semantics (code-type), and the import table is a memory-rebuilt result, so its specific function (stealer/RAT/lateral movement) cannot be confirmed.
3. The Go-side function names and string identifiers are randomized, and the mapping between the .rdata high-entropy block and the in-memory PE was not reproduced by decryption, so the static side cannot provide the payload-generation algorithm.
4. Persistence, file writes, registry or service operations were not observed, but that does not rule out the sample performing them under specific conditions.
5. Vendor naming/YARA corroboration is missing; the family attribution is marked uncertain.
6. Dynamic observation lasted about 3 minutes; long-cycle behaviors (scheduled tasks, delayed execution) may not be covered.

## Evidence index

<details>
<summary>Expand 20 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:47e7d910e0` | Sample triage | hash/imphash/per-section entropy/anomalies/packing score: 8 sections, imports from only 1 DLL (46 items), .rdata entropy 7.162, no anomalies, packing=0 |
| `ref:db13754f4a` | Import table parsing | import table: only kernel32, 46 functions (WriteFile/WriteConsoleW/VirtualAlloc/CreateThread/GetProcAddress etc.), imphash=d42595b695fc008ef2c56aabd8efd68e |
| `ref:01f4c5adc0` | String extraction | 6,358 ASCII strings from the main sample, including the Go build ID and monitoring-dashboard text; no flag hits |
| `ref:1131823e71` | script(buildinfo) | Go build info: path=YKMhhXyLySmb, (devel), -trimpath, CGO_ENABLED=0, GOARCH=amd64, go1.25.4 |
| `ref:61720d5ff6` | script(pclntab) | parsed Go pclntab: 1,796 functions, 22 in the main package, entry 0x90300–0xe7ac0, all function names are random identifiers |
| `ref:082e23804c` | script(pclntab pkgs) | linked package list is standard library only: bufio/bytes/errors/io/math/os/slices/sort/strconv/strings/sync/syscall/time/unicode, no net/crypto/compress |
| `ref:381a2e761e` | decompile.function | main.Cccntqygoqiewrjahjbr @0x1400e4300: consecutive printstring calls output the fake monitoring-dashboard titles, 8-node status statistics and percentages |
| `ref:f59b5da56d` | decompile.function | main.main @0x1400e7ac0: a giant function with a ~1.17MB stack frame; only the entry was identified, pseudocode empty |
| `ref:b83ccc5a04` | script(callsite) | call-site locations: main.xcwal→LazyProc.Find(0xc6d00)/SyscallN(0xc6d4f), main.etmrhfknxqoan→LazyProc.Call(0xe28b1) |
| `ref:18c26ab11f` | disasm.function | main.xcwal from 0xc6c40: mov rax,[rip+0x239675] loads the lazy-procedure pointer, then call syscall.(*LazyProc).Find, test/jne handles the error |
| `ref:89a767b436` | disasm.function | main.etmrhfknxqoan from 0xe2820: builds arguments, then call syscall.(*LazyProc).Call @0x14007ba60 |
| `ref:df1d768ab1` | script(entropy) | block entropy scan: 64KB blocks in 0x160000–0x274000 have entropy 7.996–7.998, forming an approx. 1.1MB high-entropy block; only the sample itself has a valid PE header |
| `ref:f607e16343` | Dynamic analysis platform | dynamic run: pid 6952 identified and dumped (16 files), no new child processes (candidates=0), no ransom notes, rolled back after containment |
| `ref:3e56e28918` | sandbox(memory forensics report) | scan_report/dump_report: implanted_pe=1, module=220000000, size=0x25a000, MEM_PRIVATE, protection=40, is_listed_module=0, 4 sections, dump_mode=REALIGNED |
| `ref:8c7ec44593` | sandbox(artifact unpacking) | extracted the memory image 220000000.exe (2,468,642 bytes) plus the rebuilt import table and ETW events (process image, command line, hashes, dump actions) |
| `ref:869b04e902` | pe.imports(payload) | in-memory payload imports: 40 DLLs with 1 item each, including 27 ntdll Nt* native APIs, 8 bcrypt BCrypt*, user32.GetSystemMetrics/wvsprintfA etc. |
| `ref:048e08b4d3` | pe.parse(payload) | payload structure: PE32+ AMD64, 4 sections (.text 1.1MB/.rdata 28KB/.data 1.3MB/.reloc), GUI subsystem, unsigned, entry RVA 0xEA080 |
| `ref:7ee0967282` | sandbox(timeline/network log) | timeline: process started at 00:34, dumped twice, observed until 00:37; network monitoring log contains only Windows Update/OCSP requests from system components, no sample traffic |
| `telemetry:bb7bc212` | Dynamic telemetry | dynamic telemetry recorded: 122 process/file events from the monitoring component; 1 ETW short-lived process event; 22 tool/system noise events filtered out |
| `etw:bb7bc212:6952` | Process event monitoring | short-lived process event: bb7bc21269b543e669840e8771b6729ee254ccfe989115c0c8c6216175e7a0c1.exe (pid 6952; MD5=FBDAE5E7BFA0B44A6FFA2E2D0DB8089D,SHA256=BB7BC21269B543E669840E8771B6729EE254CCFE989115C0C8C6216175E7A0C1,IMPHASH=D42595B695FC008EF2C56AABD8EFD68E) |

</details>

---

_The sample in this report is not public; the IOCs have been defanged and are provided for security research only._
