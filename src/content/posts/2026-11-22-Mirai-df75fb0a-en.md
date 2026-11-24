---
title: "Malware Analysis: Mirai (ELF · elf · df75fb0a)"
published: 2026-11-22
draft: false
description: "Malicious (medium confidence): Mirai · loader/dropper · medium difficulty · static decompilation (dynamic execution produced no runtime behavior)"
tags: ["Mirai", "loader", "dropper", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-Mirai-df75fb0a"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Mirai** (uncertain) · Confidence **Medium**
> 
> Aliases: Linux/Mirai, Mirai-family IoT downloader
> 
> This is a Linux x86-32 downloader-style loader: after startup it sends an HTTP GET reporting host information to the hardcoded address 144.202.10[.]28:80, decrypts the response body with single-byte XOR 0x99 into a memfd anonymous memory file, and executes it directly via fexecve with the spoofed process name [kworker/0:2], leaving nothing on disk. The decompiled main function fully reconstructs this chain, and its malicious nature is clear.

## Overview

| Item | Content |
|:--|:--|
| Family | **Mirai** · aliases Linux/Mirai, Mirai-family IoT downloader · _uncertain_ |
| Confidence | **Medium** |
| Behavior classes | loader · dropper |
| Difficulty | medium |
| First seen | 2026-11-22 02:41:13 |
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Check single-instance lock file</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Connect hardcoded C2</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reconnect every 10 s on failure</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Report host arch and port</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Fixed 1KB send leaks stack</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1` |
| MD5 | _Not recorded_ |
| Size | 7,262 bytes (7.1 KB) |
| Type | ELF · `elf` |

## Behavior Analysis

**9** behaviors in total, each backed by evidence, and all are static.

### 1. Check Single-Instance Lock File

`T1106` · Confidence **High** · Static

On startup it calls access("/tmp/log_de.log", F_OK); if the path already exists it exits immediately with exit(0), avoiding repeated runs on the same host. No write or delete of that file is present in the code.

> **Evidence**: 0x8048707 call access(0x8048ae0="/tmp/log_de.log", F_OK); 0x8048718 branch call exit(0)
> 
> **Source**: `ref:a488caeea3`

### 2. Connect Hardcoded C2

`T1071.001` · Confidence **High** · Static

Creates a socket with AF_INET/SOCK_STREAM, resolves 144.202.10[.]28 first with gethostbyname and on failure with inet_addr, then connects to port 80.

> **Evidence**: 0x804872f push 0x8048af0("144.202.10[.]28"); 0x8048784 call socket(2,1,0); 0x80487be call connect
> 
> **Source**: `ref:a488caeea3` · `ref:653e590c61`

### 3. Reconnect Every 10 Seconds on Failure

`T1071.001` · Confidence **High** · Static

When connect returns -1 it sleeps 10 seconds and retries unconditionally, forming a resident connection loop with no backoff limit.

> **Evidence**: 0x80487ce call sleep(0xa); 0x80487d6 jmp 0x80487b9 retry connect
> 
> **Source**: `ref:653e590c61`

### 4. Report Host Architecture and Port

`T1071.001` · Confidence **High** · Static

After a successful connection it uses sprintf to assemble the request GET /?a=l32&h=144.202.10[.]28&t=ws_&p=80, whose parameters carry the architecture tag, C2 address, campaign tag and port; the User-Agent masquerades as Firefox 48 on Windows.

> **Evidence**: 0x8048808 call sprintf, format string at 0x8048b19 contains the UA; parameters 0x8048b15="l32", 0x8048b11="ws_", 0x8048af0=C2 IP
> 
> **Source**: `ref:9253ac91e0` · `ref:653e590c61`

### 5. Fixed 1KB Send Leaks Stack

`T1041` · Confidence **High** · Static

The send length argument is fixed at 0x400 (1024) bytes while the request string is shorter, so uninitialized stack content behind the buffer is sent to the C2 as well.

> **Evidence**: 0x8048814 push 0x400; 0x804881b call send
> 
> **Source**: `ref:653e590c61`

### 6. Read HTTP Response Headers

`T1071.001` · Confidence **High** · Static

Receives the response byte by byte until CRLFCRLF is encountered and then enters the payload-receiving stage, indicating the second-stage data follows immediately after the HTTP headers.

> **Evidence**: 0x804883a call recv(...,1,0); 0x804886c/0x8048874 compare 0x0a/0x0d to detect CRLFCRLF
> 
> **Source**: `ref:a488caeea3`

### 7. XOR 0x99 Payload Decryption

`T1027` · Confidence **High** · Static

Each received response-body byte is XORed with 0x99 and written into the memory file, forming a single-byte XOR custom-encrypted payload channel.

> **Evidence**: 0x80488c2 xor byte ptr [edx+ecx], 0x99, looping until the recv length eax
> 
> **Source**: `ref:653e590c61` · `ref:d56a14c4b3`

### 8. Write Second Stage into memfd

`T1620` · Confidence **High** · Static

Calls syscall 356 (memfd_create, i386) with the name "a" and flag MFD_CLOEXEC(1), writing the decrypted second stage into that anonymous memory file so no file remains on disk.

> **Evidence**: 0x804887b push 1(MFD_CLOEXEC); 0x804887d push 0x8048b9c("a"); 0x8048882 push 0x164(356=memfd_create); 0x8048887 call syscall
> 
> **Source**: `ref:d56a14c4b3`

### 9. Spoofed kworker In-Memory Execution

`T1036.005` · Confidence **High** · Static

Calls realpath to obtain its own path and writes it into the CWD environment variable, then executes the memfd second stage directly via fexecve with argv[0]="[kworker/0:2]", disguising the process name as a kernel worker thread.

> **Evidence**: 0x80488fa call realpath; 0x804891a call setenv("CWD"); 0x8048930 mov [ebp-0x1c30],0x8048ba2("[kworker/0:2]"); 0x8048944 call fexecve
> 
> **Source**: `ref:d56a14c4b3` · `ref:9253ac91e0`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: The addresses above were obtained statically; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://144[.]202[.]10[.]28/` | 80 | c2 | static | ⏳ Not observed |

### Host

**Drop paths**

- `/tmp/log_de.log`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `144.202.10[.]28` | Yes | static |
| `c2_port` | `80` | Yes | static |
| `c2_uri` | `GET /?a=l32&h=<host>&t=ws_&p=<port> HTTP/1.1` | Yes | static |
| `campaign_tag` | `ws_` | No | static |
| `arch_tag` | `l32` | Yes | static |
| `lock_file` | `/tmp/log_de.log` | No | static |
| `memfd_name` | `a` | No | static |
| `payload_xor_key` | `0x99` | Yes | static |
| `process_name` | `[kworker/0:2]` | No | static |
| `user_agent` | `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` | No | static |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not claim the sample created /tmp/log_de.log: the code only checks existence (access F_OK), no write logic is present, and no file event was obtained dynamically.
- Do not claim it successfully connected to C2, downloaded or executed the second stage: there is no session/response evidence, and both C2 and stage2 are static recoveries not dynamically verified.
- Do not describe this 7KB loader directly as a bot with full DDoS capability: the DDoS functionality should be in the second stage, which was not retrieved.
- Do not claim persistence: the sample does not involve cron, systemd, rc.local, init scripts or service registration.
- Do not claim it is a specifically named variant: the sample contains no family name/version/config ID strings, and the family determination is a same-family candidate.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Unpacked | No |

**Limitations and pending verification**

1. The hardened dynamic-analysis instance produced no runtime events, and this run obtained no process, network or file-level dynamic observations; all conclusions come from static decompilation and disassembly.
2. C2 was not actually reached: only a statically constructed request format exists, with no response or callback session, so C2 is marked as static recovery and remains pending dynamic verification.
3. The second stage was not retrieved, and the content after XOR 0x99 decryption is unknown, so the final bot functionality, full attack surface and exact family name cannot be confirmed.
4. The precise meaning of the request parameter t=ws_ (campaign/build tag) cannot be determined from the sample and is recorded literally.
5. The fixed 1024-byte send leaks stack content, but the leaked content depends on the runtime stack layout and cannot be determined statically.
6. The sample is i386; if the target environment lacks 32-bit runtime libraries it cannot start, and the actual infection success rate cannot be assessed.

## Evidence Index

<details>
<summary>Expand 7 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:1743a77db2` | ELF structure parse | i386 32-bit EXEC, entry 0x80485e4, depends on libc.so.6, no structural anomalies; imports socket/connect/gethostbyname/fexecve/syscall/realpath/setenv etc. |
| `ref:6cf72d5725` | ELF section table | .text 992 bytes (entropy 6.06), .rodata 216 bytes; no high-entropy encrypted section, consistent with a small loader |
| `ev-000001` | String scan | Hits /tmp/log_de.log, 144.202.10[.]28, GET /?a=%s&h=%s&t=%s&p=%d, Host/UA templates, [kworker/0:2], linux_i386_ws.c |
| `ev-000002` | Decompilation | Full main recovery: access single-instance check→connect 80→build GET→recv headers→syscall(memfd_create)→recv/XOR 0x99→write→realpath/setenv→fexecve([kworker/0:2]) |
| `ref:653e590c61` | Disassembly | Instruction-by-instruction confirmation of connect/sleep retry, sprintf arguments, send 0x400, recv CRLF detection |
| `ref:d56a14c4b3` | Disassembly | Confirms syscall 0x164(memfd_create), xor 0x99 loop, setenv CWD, fexecve and argv[0]=[kworker/0:2] |
| `ref:a6836b0bf2` | Cryptographic constant scan | No AES/SHA/MD5/TEA standard algorithm constants found, consistent with single-byte XOR obfuscation |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
