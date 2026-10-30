---
title: "Malware Analysis: Linux DHT-P2P botnet (B1txor20/Pink/Fodcha lineage candidate) (ELF · elf · 06bbe6f0)"
published: 2026-10-28
draft: false
description: "Malicious (low confidence): Linux DHT-P2P botnet (B1txor20/Pink/Fodcha lineage candidate) · botnet/backdoor · difficulty medium · emulation"
tags: ["botnet", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-28-linux-dht-botnet-06bbe6f0"
---

> [!WARNING]
> **Verdict: malicious** · Family **Linux DHT-P2P botnet (B1txor20/Pink/Fodcha lineage candidate)** (uncertain) · Confidence **low**
> 
> Aliases: B1txor20, Pink, Fodcha, DHT botnet
> 
> Static reconstruction recovered the self-extracted PPC main program: it builds BitTorrent DHT (KRPC) messages, verifies Ed25519 signatures, contains ChaCha20 crypto constants, executes commands via /bin/sh -c and uses a per-session single-instance IPC socket. On the dynamic side, the payload code actually executed inside a hardened isolated instance (it created the AF_UNIX abstract socket six_sayven-<port>, created a TCP socket and connected to 127.0.0[.]1:<port>, then called exit_group(1) after the network was refused). The malicious verdict rests on both statically determinable capability and genuine dynamic execution.

## Overview

| Item | Content |
|:--|:--|
| Family | **Linux DHT-P2P botnet (B1txor20/Pink/Fodcha lineage candidate)** · aliases B1txor20, Pink, Fodcha, DHT botnet · _uncertain_ |
| Confidence | **low** |
| Behaviour class | botnet · backdoor |
| Difficulty | medium |
| First seen | 2026-10-28 13:58:35 |
| Analysis method | emulation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/06bbe6f0d5549fc7e781c5cc0d411285d963aae4b1747c87b05a686cfe1fe8ff/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Self-extracts the LZMA main payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Parses its own file path</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1083</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Binds a single-instance abstract socket</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1559</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Probes the loopback network then exits</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Joins the BitTorrent DHT network</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `06bbe6f0d5549fc7e781c5cc0d411285d963aae4b1747c87b05a686cfe1fe8ff` |
| MD5 | _not recorded_ |
| Size | 124,688 bytes (121.8 KB) |
| Type | ELF · `elf` |

## Behaviour analysis

**8** behaviours were recovered, each with supporting evidence; **6** are static and **2** come from dynamic analysis.

### 1. Self-extracts the LZMA main payload

`T1027.002` · confidence **high** · static

From entry point 0x1009d228 there is a UPX-LZMA unpacking stub (it initialises a 0x400-entry probability table and derives lc/lp/pb from the first byte) that at runtime unpacks roughly 330,000 bytes of PPC main program; the packed file has an overall entropy of 7.994 and every static string is ciphertext.

> **Evidence**: the 'UPX!' marker exists at file offsets 0x98/0x1e6e3, method=0x0e(LZMA); 0x1009d228 stwu/mflr + 0x400 probability table fill
> 
> **Source**: `ref:92f0dbaf1c` · `ref:3708f7b05f` · `ref:d23c115519`

### 2. Parses its own file path

`T1083` · confidence **medium** · static

The recovered code references '/proc/self/exe' along with path-joining strings such as '%s/%s', '..' and '.', used to locate and reuse its own executable path (self-copy/restart).

> **Evidence**: recovered block 2 offset 0x77 '/proc/self/exe' (near virtual address 0x100d00ff), plus 0x4d15c '%s-%u' and 0x4d17c '%s/%s'
> 
> **Source**: `ref:6604bda969` · `ref:5d3d80dbfa`

### 3. Binds a single-instance abstract socket

`T1559` · confidence **high** · dynamic

Using '%s-%u' it generates the name 'six_sayven-<port>' and binds it to an AF_UNIX abstract address, serving as a local single-instance/inter-process coordination marker.

> **Evidence**: dynamic event bind(0, {sa_family=AF_UNIX, sun_path=@"six_sayven-63464"}) = 0; the string six_sayven sits at 0x4d164 in the recovered image
> 
> **Source**: `ref:f9cc3e7b77` · `ref:6604bda969` · `ref:f8f55147ca`

### 4. Probes the loopback network then exits

`T1016` · confidence **high** · dynamic

After closing 0/1/2 it creates a TCP socket, sets SO_SNDTIMEO and connects to 127.0.0[.]1:<same port>; in the network-isolated environment the call returns ENETUNREACH and the sample calls exit_group(1), showing that it treats local connectivity as a precondition for the rest of its flow.

> **Evidence**: trace: close(0/1/2) → socket(AF_INET) → setsockopt(SO_SNDTIMEO) → connect(..., htons(63464), 127.0.0[.]1) = -1 ENETUNREACH → exit_group(1)
> 
> **Source**: `ref:f9cc3e7b77` · `ref:f8f55147ca`

### 5. Joins the BitTorrent DHT network

`T1071` · confidence **high** · static

The payload contains complete KRPC message templates and can issue get/put/ping/get_peers queries to the DHT and handle the nodes/token/info_hash/target fields — that is, it sends and receives instructions over the BitTorrent DHT overlay, with no fixed C2 address.

> **Evidence**: recovered image 0x4d343 '*d1:ad2:id20:', 0x4d3bc 'e1:q9:get_peers1:t2:', 0x4d384 'e1:q3:put1:t2:', 0x4d3ac '9:info_hash20:', 0x4d400 'id'/'sig'/'seq'/'token'
> 
> **Source**: `ref:6604bda969` · `ref:5d3d80dbfa`

### 6. Verifies Ed25519-signed commands

`T1553.002` · confidence **high** · static

It embeds an Ed25519 implementation and the domain-separation string 'SigEd25519 no Ed25519 collisions', and together with the sig64/seq/v fields it signs and sequence-checks the instructions delivered over the DHT, preventing them from being forged or replayed.

> **Evidence**: recovered image 0x4d460 'SigEd25519 no Ed25519 collisions', 0x4d35c '3:seqi%llde3:sig64:'
> 
> **Source**: `ref:6604bda969` · `ref:5d3d80dbfa`

### 7. ChaCha20 encryption and encoding

`T1573` · confidence **high** · static

The ChaCha20 constant 'expand 32-byte k' and the z-base-32 alphabet 'ybndrfg8ejkmcpqxot1uwisza345h769' are present, used to encrypt and decrypt DHT payloads and for compact encoding.

> **Evidence**: recovered image 0x4e5cc 'expand 32-byte k', 0x4d43c z-base-32 table
> 
> **Source**: `ref:6604bda969` · `ref:5d3d80dbfa`

### 8. Executes commands through a shell

`T1059.004` · confidence **high** · static

The payload contains the '/bin/sh', 'sh' and '-c' combination, giving it the ability to hand remotely delivered strings to the system shell for execution (the botnet command-execution surface).

> **Evidence**: recovered image 0x4d220 '/bin/sh', 0x4d226 'sh', 0x4d22c '-c'
> 
> **Source**: `ref:6604bda969` · `ref:5d3d80dbfa`


## IOC (defanged)

### Network

:::caution
**Still unverified on the real server side**: the connections/handshakes above were completed with a locally controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| other | `BitTorrent DHT overlay (KRPC: get/put/get_peers/ping, messages Ed25519-signed, z-base-32/ChaCha20 encoded)` | - | c2 | static | ⏳ not observed |
| dns | `2001:4860:4860[::]8888` | 53 | c2 | static | ⏳ not observed |

### Host

**Mutex**

- `AF_UNIX abstract socket six_sayven-<random port> (single-instance marker)`

**Drop paths**

- `/proc/self/exe`
- `/bin/sh`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_transport` | `BitTorrent DHT (KRPC over UDP)` | yes | static |
| `dht_queries` | `get / put / get_peers / ping, fields id/info_hash/token/nodes/target/sig/seq` | yes | static |
| `dht_command_auth` | `Ed25519 (sig64 + seq + v)` | yes | static |
| `encryption_algo` | `ChaCha20 ('expand 32-byte k') + z-base-32 encoding` | yes | static |
| `dns_resolver` | `2001:4860:4860::8888` | no | static |
| `command_shell` | `/bin/sh -c` | yes | static |
| `singleton_id` | `six_sayven-%u` | yes | static |
| `build_stamp` | `Jan 5 2022 14:22:37` | no | static |
| `target_arch` | `ppc (32-bit big-endian)` | yes | static |
| `c2_hosts` | `not recovered: no fixed IP/domain; instructions are distributed over the DHT overlay by info_hash` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- The sample has no readable fixed-IP/domain C2, so it must not be described as a conventional HTTP/DNS panel C2; its command channel is the BitTorrent DHT overlay.
- No code or behavioural evidence of ransomware, wipers or browser credential theft was found; it must not be classified as ransomware/wiper/stealer.
- No real outbound connection was observed: the only connect target was 127.0.0[.]1 and the isolated network refused it with ENETUNREACH, so this cannot be used to claim that a C2 server has been located or reproduced.
- The string 'wow i guess im finna bridge now' in the run log is not sample output (the sample makes no write calls at all after closing 0/1/2) and must not be treated as a sample signature.
- No DDoS traffic or evidence of attack instructions being executed was observed, so the sample cannot be claimed to have a directly usable DDoS impact.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | emulation |
| Unpacked | yes (stage2 `e95b76c2d7058fb6302c9b3ed0f38e55629bb0c5fa522161e7da3cea2f0f358f`) |

**Limitations and open questions**

1. Packing leaves every static string encrypted, so both strings and logic come from self-extraction (the LZMA block boundaries were determined step by step during stream decoding); about 13.7 KB of the recovered image remains uncovered.
2. The isolated environment has no network; after connect 127.0.0[.]1 returns ENETUNREACH the sample immediately exits(1), so the DHT stage and command execution never reached a real network — hence C2/info_hash are marked as statically recovered and pending dynamic verification.
3. Family attribution rests only on a combination of capability fingerprints (DHT+Ed25519+ChaCha20+z-base-32) and lacks independent confirmation from vendor engines or YARA, so it is treated as a candidate.
4. The definite location of the DHT public key / 20-byte info_hash was not obtained, so reproducible node-location information cannot be given.
5. This sample is PPC architecture and cannot be executed natively on x86; dynamic observations come only from cross-architecture user-mode emulation and syscall tracing.

## Evidence index

<details>
<summary>Show 17 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:aea59b70e6` | ELF structure parse | packed ELF structure: PPC32 big-endian EXEC, no interp/symbols/imports, 3 segments (RW 0x10000000 filesz 0x1000 memsz 0x751d8; RX 0x10080000 filesz 0x1e600) |
| `ref:165ba42849` | elf.sections | segment table: RW-/R-X/GNU_STACK, no section table (removed by packing) |
| `ref:3708f7b05f` | scan.entropy | whole-file entropy 7.994, consistent with an encrypted/compressed packer |
| `ref:e95607e7a5` | string extraction | packed state yields only 539 meaningless ASCII strings, with no readable configuration or C2 |
| `ref:92f0dbaf1c` | disasm.function | disassembly at entry 0x1009d228: stack probing + bit operations, an unpacking stub rather than business code |
| `ref:f8f55147ca` | emu.qemu | cross-architecture emulated execution, exit=0 record, arch=ppc, isolated without network (unshare -n) |
| `ref:4e04f06eab` | bash | retrieved emulation artefacts: detonate.json/stdout.txt/stderr.txt/trace.log |
| `ref:f9cc3e7b77` | bash | syscall trace: guest closes 0/1/2, bind AF_UNIX @six_sayven-63464, connect 127.0.0[.]1:63464=ENETUNREACH, exit_group(1) |
| `ref:d23c115519` | bash | custom LZMA block location and decompression (lc3/lp0/pb2), recovering a 0x5160d-byte image and building a parsable ELF |
| `ref:5d3d80dbfa` | bash | hashes: original sample sha256 and recovered-image sha256 e95b76c2…f358f |
| `ref:af3adea1e3` | ELF structure parse | recovered ELF parses successfully: single R-X segment 0x10080000, size 333325, entry 0x10080000 |
| `ref:da6ec3d99a` | decompile.symbols | 3356 functions identified after recovery (static libc + main program), confirming the payload is an executable PPC program |
| `ref:b4d42e2211` | decompile.function | decompiled 0x10080024: __libc_csu_init-style init array walk, consistent with a standard static uClibc program structure |
| `ref:59e1300f47` | decompile.function | decompiled 0x100800e0: libc startup helper routine, returns the .data base address |
| `ref:6604bda969` | string extraction | recovered strings: DHT KRPC templates, Ed25519 domain-separation string, z-base-32 table, expand 32-byte k, /bin/sh, six_sayven, 2001:4860:4860::8888, ppc, Jan 5 2022 14:22:37 |
| `ref:5bc6fef3da` | bash | capstone scanned 56973 instructions and found no direct lis 0x100c/0x100d string loads (addressing goes indirectly through the TOC/data tables) |
| `ref:7k8suqzo4` | bash | attempts to locate brand/family strings (pink/aisuru/fodcha/mirai etc.) all failed, supporting the need to rely on capability fingerprints for family attribution |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
