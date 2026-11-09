---
title: "Malware Analysis: XorDdos (ELF · elf · f8c2baa8)"
published: 2026-11-08
draft: false
description: "Malicious (medium confidence): XorDdos · downloader/loader/backdoor · difficulty medium · Dynamic sandbox analysis + static decompilation"
tags: ["XorDdos", "downloader", "loader", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-08-XorDdos-f8c2baa8"
---

> [!WARNING]
> **Verdict: Malicious** · Family **XorDdos** (uncertain) · Confidence **medium**
> 
> Aliases: XOR.DDoS, Linux.XorDdos, ELF/XorDdos
> 
> Decompilation and disassembly show the program is a downloader/loader that only performs a TCP check-in, receives a XOR(0x99)-encrypted payload, writes it to an in-memory file and executes it directly via fexecve; running it for real in the isolated environment observed repeated connections to 124.222.69[.]132:8085 (retrying every 10 seconds when the network was unreachable), which constitutes implemented and reproducible malicious C2 communication and remote-code-execution staging.

## Overview

| Item | Content |
|:--|:--|
| Family | **XorDdos** · aliases XOR.DDoS, Linux.XorDdos, ELF/XorDdos · _uncertain_ |
| Confidence | **medium** |
| Behavior class | downloader · loader · backdoor |
| Difficulty | medium |
| First seen | 2026-11-07 01:40:21 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Probe marker file</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Connect to C2 and retry</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Send l64 fingerprint</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">XOR-decrypt payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Execute from memory</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb` |
| MD5 | _not recorded_ |
| Size | 9,800 bytes (9.6 KB) |
| Type | ELF · `elf` |

## Behavior analysis

**6** behaviors in total, each backed by evidence; **4** are statically available and **2** were obtained through dynamic analysis.

### 1. Probe marker file

`T1480` · Confidence **high** · dynamic

At startup it calls access("/tmp/log_de.log", F_OK); if the file exists it calls exit(0), and only when it does not exist does execution continue into the check-in logic.

> **Evidence**: 0x400967 call access("/tmp/log_de.log",0); after the conditional jump at 0x40096e, 0x400972 call exit(0); dynamic tracing shows access returning ENOENT
> 
> **Source**: `ev-000015` · `ev-000007`

### 2. Connect to C2 and retry

`T1095` · Confidence **high** · dynamic

It resolves/fills in 124.222.69[.]132, calls socket(AF_INET,SOCK_STREAM,0), sets TCP_SYNCNT=10, and connects to port 8085; if connect fails it sleeps 10 seconds and retries indefinitely.

> **Evidence**: 0x400a1b call connect; 0x400a29 call sleep(10); dynamic event connect(sin_port=htons(8085), sin_addr=124.222.69[.]132)=-1 ENETUNREACH, followed by clock_nanosleep 10s and another retry
> 
> **Source**: `ev-000013` · `ev-000015`

### 3. Send l64 fingerprint

`T1095` · Confidence **high** · static

After connecting it sends, in order, the 6-byte "l64 ", the 2-byte network-order port (0x1f 0x95, i.e. 8085), and a 32-byte buffer containing the C2 IP string, as a check-in handshake/identity.

> **Evidence**: 0x400a3e call send(fd,"l64 ",6); 0x400a62 sends the two port bytes; 0x400a75 sends the 0x20-byte buffer
> 
> **Source**: `ev-000015` · `ev-000001`

### 4. XOR-decrypt payload

`T1140` · Confidence **high** · static

It loops on recv for up to 0x1000 bytes and XORs every received byte with 0x99 to obtain the plaintext payload.

> **Evidence**: 0x400abd xor byte ptr [rax],0x99 byte-by-byte loop; decompilation shows *pbVar7 = *pbVar7 ^ 0x99
> 
> **Source**: `ev-000015`

### 5. Execute from memory

`T1620` · Confidence **high** · static

syscall(319, "a", 0) creates a memfd, the decrypted payload is written into that anonymous file, and fexecve finally executes it directly from memory without touching disk.

> **Evidence**: 0x400a88 mov edi,0x13f; call syscall => memfd_create("a",0); 0x400ad4 call write(memfd, buf, len); 0x400b37 call fexecve
> 
> **Source**: `ev-000015`

### 6. Masquerade as kernel thread

`T1036.005` · Confidence **high** · static

Before executing the payload it calls realpath(argv[0]) to obtain its own path and setenv("CWD", path, 1), and sets argv[0] to "[kworker/0:2]" to masquerade as a kernel worker thread.

> **Evidence**: 0x400af9 call realpath; 0x400b0f call setenv("CWD",...); 0x400b25 loads "[kworker/0:2]" at 0x400cf1 as argv[0]
> 
> **Source**: `ev-000015` · `ev-000001`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `124.222.69[.]132` | 8085 | c2 | static | ⏳ not observed |

### Host

**Dropped paths**

- `/tmp/log_de.log`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `124.222.69[.]132` | yes | static |
| `c2_port` | `8085` | yes | static |
| `transport` | `raw TCP (AF_INET/SOCK_STREAM), setsockopt IPPROTO_TCP/TCP_SYNCNT=10, 10s reconnect interval` | yes | static |
| `handshake` | `6-byte banner 'l64 ' + 2-byte network-order port + 32-byte buffer containing the C2 IP string` | yes | static |
| `encryption_algo` | `single-byte XOR 0x99 applied to received payload` | yes | static |
| `memfd_name` | `a` | yes | static |
| `argv0_masquerade` | `[kworker/0:2]` | yes | static |
| `env_var` | `CWD=<realpath of the sample>` | no | static |
| `marker_path` | `/tmp/log_de.log` | yes | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not assert that the sample successfully connected to the C2 or downloaded a second-stage payload: the isolated environment only observed connect attempts and ENETUNREACH, with no request/response session.
- Do not assert that a persistence mechanism exists: no writes to systemd, cron, rc scripts, services or scheduled tasks were observed.
- Do not classify it as ransomware, wiper or miner: the code contains no file-encryption, deletion or mining logic or constants.
- Do not describe /tmp/log_de.log as a log or configuration written by the sample: the sample only checks for its existence and exits immediately if present.
- Do not treat argv[0] "[kworker/0:2]" as a real kernel thread or real process name.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The dynamic run was in a network-isolated environment; every connect returned ENETUNREACH and no C2 session was established, so protocol details and the second-stage payload can only be recovered statically, and the C2 is marked static with pending_dynamic_verify.
2. The delivered second-stage ELF was not obtained, so its final capability (DDoS, backdoor or other) cannot be confirmed.
3. Family attribution is based on code features (XOR 0x99, memfd+fexecve, [kworker/0:2] masquerade, l64 handshake) consistent with public XorDdos traits, but without YARA/multi-engine signature support, so it remains a candidate conclusion.
4. The run was terminated by timeout after about 20 seconds, so long-term behavior was not observed; /tmp/log_de.log was not observed being created or persistently written.
5. Static analysis is based on a single main function plus CRT stubs, and no other business functions or additional hidden configuration were found.

## Evidence index

<details>
<summary>Expand 6 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | static.strings | Extracted key strings such as "/tmp/log_de.log", "l64 ", "CWD", "[kworker/0:2]" and "124.222.69[.]132" |
| `ev-000007` | dynamic.syscall_trace | access("/tmp/log_de.log", F_OK) returned -1 ENOENT |
| `ev-000012` | dynamic.syscall_trace | socket(AF_INET, SOCK_STREAM, IPPROTO_IP) returned 3 |
| `ev-000013` | dynamic.syscall_trace | connect to 124.222.69[.]132:8085 returned ENETUNREACH |
| `ev-000014` | dynamic.syscall_trace | Another connect to the same C2 10 seconds later also returned ENETUNREACH |
| `ev-000015` | static.decompile | main decompilation: marker check -> resolve/connect C2 -> retry -> send l64 handshake -> recv and XOR 0x99 -> memfd -> fexecve("[kworker/0:2]") |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
