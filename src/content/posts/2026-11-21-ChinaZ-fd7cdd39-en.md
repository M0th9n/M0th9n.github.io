---
title: "Malware sample analysis: ChinaZ (ELF · elf · fd7cdd39)"
published: 2026-11-21
draft: false
description: "Malicious (low confidence): ChinaZ · downloader/dropper · difficulty medium · static decompilation (dynamic execution yielded no runtime behavior)"
tags: ["ChinaZ", "downloader", "dropper", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-21-ChinaZ-fd7cdd39"
---

> [!WARNING]
> **Verdict: malicious** · family **ChinaZ** (uncertain) · confidence **low**
> 
> Aliases: AES.DDoS, Linux/AES.DDoS, Linux.ChinaZ
> 
> The sample is a 32-bit i386 ELF downloader/dropper. After starting, it connects to the hardcoded address 179.199.199[.]11:8080, sends an HTTP GET heartbeat carrying a host identifier, receives the stage-2 payload on the same TCP connection, decrypts it with single-byte XOR 0x99, writes it to an anonymous memory file created by memfd_create, and then executes it directly via fexecve, while masquerading the process name as [kworker/0:2]. The above logic was fully reconstructed by disassembly and decompilation, forming a clear malicious download-and-memory-execution chain.

## At a glance

| Item | Value |
|:--|:--|
| Family | **ChinaZ** · aliases AES.DDoS, Linux/AES.DDoS, Linux.ChinaZ · _uncertain_ |
| Confidence | **low** |
| Behavior class | downloader · dropper |
| Difficulty | medium |
| First seen | 2026-11-19 01:29:19 |
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Connects hardcoded C2, retries</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Sends HTTP heartbeat</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reads response header boundary</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Creates anonymous memory file</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Receives and XOR-decrypts payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a` |
| MD5 | _not recorded_ |
| Size | 7,262 bytes (7.1 KB) |
| Type | ELF · `elf` |

## Behavior analysis

**7** behaviors in total, each with evidence attached, all of them statically obtainable.

### 1. Connects hardcoded C2, retries

`T1071.001` · confidence **high** · static

The program writes 179.199.199[.]11:8080 into sockaddr_in, creates a TCP socket, and calls connect; on failure it sleeps 10 seconds and retries until success or socket creation fails.

> **Evidence**: 0x8048784 socket(2,1,0); 0x80487b1 setsockopt(fd,6,7,&10,4); 0x80487be connect(fd,&sa,16); 0x80487d8 sleep(10) retry
> 
> **Source**: `ref:dc26c3330e` · `ref:b56aedfea8` · `ref:b2427518c8`

### 2. Sends HTTP heartbeat

`T1071.001` · confidence **high** · static

After connecting, it uses sprintf to build a GET /?a=l32&h=179.199.199[.]11&t=ws_&p=8080 HTTP/1.1 request with Host and a Firefox 48 User-Agent, sent via send in one 0x400-byte write.

> **Evidence**: 0x8048808 sprintf uses the request template at 0x8048b19; 0x80487f5-0x8048803 pushes arguments a=l32, h=179.199.199[.]11, t=ws_; 0x804881b send(fd,buf,0x400,0)
> 
> **Source**: `ref:dc26c3330e` · `ref:b56aedfea8` · `ref:0a2627f845`

### 3. Reads response header boundary

`T1071.001` · confidence **high** · static

The program recv's the server response byte by byte, appending bytes to a stack buffer, and stops reading when it detects \r\n\r\n, so that the stage-2 payload in the response body can be read next.

> **Evidence**: 0x804883a recv(fd,buf+3,1,0); from 0x8048860 it compares the four-byte 0x0a/0x0d sequence and jumps out of the loop on a match
> 
> **Source**: `ref:dc26c3330e` · `ref:b56aedfea8`

### 4. Creates anonymous memory file

`T1620` · confidence **high** · static

It calls syscall(0x164), i.e. memfd_create("a", MFD_CLOEXEC), to create a pathless anonymous memory file as the container for the stage-2 payload, avoiding a disk write.

> **Evidence**: 0x8048887 call syscall with arguments 0x164(356=memfd_create), 0x8048b9c("a"), 1(MFD_CLOEXEC)
> 
> **Source**: `ref:dc26c3330e` · `ref:b56aedfea8`

### 5. Receives and XOR-decrypts payload

`T1140` · confidence **high** · static

It loops recv over the response body in 0x1000-byte chunks, XORs each byte with 0x99, and writes the decrypted result into the memfd until recv returns a non-positive value.

> **Evidence**: 0x80488ae recv(fd,buf,0x1000,0); 0x80488c2 xor byte ptr [edx+ecx],0x99; 0x80488d5 write(memfd,buf,n)
> 
> **Source**: `ref:dc26c3330e` · `ref:b56aedfea8`

### 6. Executes stage 2 in memory

`T1620` · confidence **high** · static

After decryption it closes the socket and calls fexecve to execute the stage-2 ELF directly from the memfd, so the payload is never written to the regular filesystem.

> **Evidence**: 0x8048944 call fexecve(memfd, argv, environ); after execution 0x80488fa/0x8048951 close again
> 
> **Source**: `ref:dc26c3330e` · `ref:b56aedfea8`

### 7. Masquerades as kernel worker thread

`T1036.005` · confidence **high** · static

Before execution it sets argv[0] to "[kworker/0:2]" and uses setenv to set the environment variable CWD to its own realpath, making the stage-2 process name masquerade as a kernel worker thread.

> **Evidence**: 0x8048930 argv[0]=0x8048ba2 "[kworker/0:2]"; 0x804891a setenv("CWD", realpath(argv[0]), 1)
> 
> **Source**: `ref:dc26c3330e` · `ref:b56aedfea8` · `ref:0a2627f845`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://179[.]199[.]199[.]11:8080/` | 8080 | c2 | Static | ⏳ not observed |
| http | `hxxp://179[.]199[.]199[.]11:8080/` | 8080 | download | Static | ⏳ not observed |

### Host

**Dropped paths**

- `/tmp/log_de.log`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `179.199.199[.]11` | Yes | Static |
| `c2_port` | `8080` | Yes | Static |
| `c2_uri` | `/?a=l32&h=179.199.199[.]11&t=ws_&p=8080` | Yes | Static |
| `user_agent` | `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` | No | Static |
| `encryption_algo` | `single-byte XOR, key 0x99` | Yes | Static |
| `check_file` | `/tmp/log_de.log` | Yes | Static |
| `memfd_name` | `a` | Yes | Static |
| `argv0_masquerade` | `[kworker/0:2]` | Yes | Static |
| `env_var` | `CWD=<realpath(argv[0])>` | No | Static |
| `campaign_tag` | `ws_/l32` | No | Static |

## Do not misjudge

:::important
The conclusions below are **easily misjudged**; take care when citing this report.

- Do not claim that the sample itself has DDoS, ransomware, or credential-theft functionality: the first stage only downloads and executes the second stage in memory, and no attack, encryption, or data-theft code was found in the sample.
- Do not claim that the sample established a real session with the C2 or obtained the stage-2 payload: the dynamic execution environment failed to start this 32-bit program, and no network session was observed.
- Do not claim that the C2, XOR key, or masqueraded process name came from dynamic decryption: all of these come from static decompilation and string/byte extraction.
- Do not treat "[kworker/0:2]" as a real kernel thread; it is only the argv[0] masquerade value of the stage-2 process.
:::

## Analysis method and limitations

| Item | Value |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. The analysis execution environment lacks the 32-bit dynamic loader /lib/ld-linux.so.2, so the sample could not actually start, and runtime connections, process behavior, and the stage-2 payload were not observed.
2. The C2, XOR key, memfd name, and masqueraded process name are all from static decompilation, not dynamically verified, and the related entries are static with pending_dynamic_verify=true.
3. The stage-2 payload was not obtained, so its final functionality (such as DDoS or backdoor) cannot be determined, and no conclusion is drawn about stage-2 capability.
4. Family attribution is supported only by static features within the sample and lacks cross-confirmation from external engines, YARA, or public reports, so it is marked as an uncertain candidate.

## Evidence index

<details>
<summary>Expand 5 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:72254114a7` | ELF structure parsing | confirmed 32-bit i386, entry 0x80486e0, dynamic dependency on libc, imports socket/connect/send/recv/fexecve/setenv/syscall, etc. |
| `ref:0a2627f845` | String scan | extracted key strings including /tmp/log_de.log, 179.199.199[.]11, HTTP GET template, Firefox UA, "[kworker/0:2]" |
| `ref:b56aedfea8` | Decompilation | reconstructed the complete main logic: connect to C2, send heartbeat, receive payload, XOR 0x99, memfd_create, fexecve |
| `ev-000017` | Dynamic execution | real execution channel returned execve ./prog ENOENT, confirming the execution environment lacks a 32-bit loader; no sample behavior obtained |
| `ev-000019` | Cross-architecture emulation | i386 qemu-user reported it could not find /lib/ld-linux.so.2; emulation likewise failed to load the sample |

</details>

---

_This report's sample is not public, IOCs are defanged, for security research only._
