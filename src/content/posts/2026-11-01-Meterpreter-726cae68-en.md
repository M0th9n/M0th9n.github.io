---
title: "Malware Analysis: Meterpreter (ELF · elf · 726cae68)"
published: 2026-11-01
draft: false
description: "Malicious (medium confidence): Meterpreter · backdoor/loader/downloader · difficulty easy · dynamic sandbox + static decompilation"
tags: ["Meterpreter", "backdoor", "loader", "downloader", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-01-Meterpreter-726cae68"
---

> [!WARNING]
> **Verdict: malicious** · Family **Meterpreter** (doubtful) · Confidence **medium**
> 
> Aliases: Metasploit linux/x86 stager, linux/x86/meterpreter/reverse_tcp stager, linux_i386_tcp stager
> 
> Decompilation of the main function fully reconstructs the chain "single-instance lock file → TCP reverse connection to a hardcoded address → send the l32 handshake → receive and XOR-decrypt stage two byte by byte with 0x99 → anonymous memfd_create landing → fexecve execution under a masqueraded process name", and every address was cross-checked against the disassembly. The program produces no visible functionality for the local user; all logic serves remote payload delivery and execution, making it a remote-control payload stager/backdoor.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Meterpreter** · Aliases Metasploit linux/x86 stager, linux/x86/meterpreter/reverse_tcp stager, linux_i386_tcp stager · _doubtful_ |
| Confidence | **Medium** |
| Behavior classes | backdoor · loader · downloader |
| Difficulty | easy |
| First seen | 2026-10-30 00:14:15 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/726cae684af35571a565bbac17e09cd79beaa07afc036721635372b79b934b87/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Lock file prevents re-run</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Hardcoded C2 and port</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Retry every 10 seconds</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Send l32 handshake</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Receive and XOR-decrypt</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `726cae684af35571a565bbac17e09cd79beaa07afc036721635372b79b934b87` |
| MD5 | _not recorded_ |
| Size | 6,968 bytes (6.8 KB) |
| Type | ELF · `elf` |

## Behavior analysis

**8** behaviors in total, each backed by evidence, and all are obtainable statically.

### 1. Lock file prevents re-run

`T1480` · Confidence **High** · Static

Immediately on startup the program calls access("/tmp/log_de.log",0); if the file already exists it exits with exit(0), using a fixed-path lock to enforce single-instance/anti-reinfection behavior.

> **Evidence**: 0x080486d7 call access@plt(0x8048630), argument 0x08048a60="/tmp/log_de.log"; when it returns 0, 0x080486e5 call exit@plt(0x80485c0)
> 
> **Source**: `ev-000002` · `ev-000001` · `ref:5ca1f4d12b`

### 2. Hardcoded C2 and port

`T1095` · Confidence **High** · Static

The built-in remote address 172.245.80[.]41 and port 80: it first copies the string at 0x08048a8c into a stack buffer with rep movsb, falls back to inet_addr if gethostbyname fails, and fills the port into sockaddr_in as 0x5000 (network byte order).

> **Evidence**: 0x080486fa mov esi,0x08048a8c; 0x08048720 mov word [ebp-0x144a],0x5000 (port 80); 0x08048763 socket(2,1,0); gethostbyname@0x8048650 / inet_addr@0x8048660
> 
> **Source**: `ev-000002` · `ev-000001` · `ref:ce4b30f8fc`

### 3. Retry every ten seconds on failure

`T1095` · Confidence **High** · Static

When connect returns -1 it unconditionally sleeps for 10 seconds and retries, forming a persistent reconnect loop; the socket also sets SO_KEEPALIVE (level 6/opt 7/10s).

> **Evidence**: 0x0804879d call connect@plt(0x8048670); 0x080487ad push 0xa; call sleep@plt(0x80485a0); setsockopt@0x08048790
> 
> **Source**: `ev-000002` · `ref:5ca1f4d12b`

### 4. Send the l32 handshake

`T1095` · Confidence **High** · Static

After the connection is established it sends the 6-byte "l32 " identifier, the 2-byte port, and the 32-byte host string in sequence, as the stage-one (downloader) registration handshake to the controller.

> **Evidence**: 0x080487bb push 0x08048a70("l32 ")/push 6/call send@0x80486a0; 0x080487e1 send 2-byte port; 0x080487f1 push 0x20 to send the 32-byte host string
> 
> **Source**: `ev-000002` · `ev-000001` · `ref:55b5536162`

### 5. Receive and XOR-decrypt

`T1140` · Confidence **High** · Static

It loops recv(0x1000) to collect stage-two data blocks, decrypts every byte with XOR 0x99, and writes the result to an anonymous file descriptor until the peer closes.

> **Evidence**: 0x08048832 call recv@plt(0x8048680); 0x08048846 xor byte ptr [edx+ecx],0x99; 0x08048859 call write@plt(0x8048610)
> 
> **Source**: `ev-000002` · `ref:55b5536162`

### 6. memfd in-memory landing

`T1620` · Confidence **High** · Static

Creates an anonymous in-memory file named "a" via syscall 0x164 (i386 memfd_create) as the landing carrier for stage two, leaving no file on disk.

> **Evidence**: 0x08048801 push 0x164; 0x08048806 push 0x08048a77("a"); call syscall@plt(0x8048620)
> 
> **Source**: `ev-000002` · `ref:ce4b30f8fc`

### 7. Execute the payload with fexecve

`T1620` · Confidence **High** · Static

After receiving finishes it zeroes the 4KB buffer, closes the socket, and calls fexecve with argv=["[kworker/0:2]"] and environ, executing stage two directly from the memfd so the original filename and entry point leave no trace.

> **Evidence**: 0x080488c8 call fexecve@plt(0x80485e0); 0x080488b4 mov dword [ebp-0x1454],0x08048a7d("[kworker/0:2]"); 0x0804888e call realpath
> 
> **Source**: `ev-000002` · `ev-000001` · `ref:55b5536162`

### 8. Masquerade as a kernel thread

`T1036.005` · Confidence **High** · Static

When executing the payload it sets argv[0] to "[kworker/0:2]" and fills the CWD environment variable with realpath(argv[0]) before setenv, so the process appears as a kernel worker thread in process listings.

> **Evidence**: after 0x08048884 push [eax](argv[0]), 0x0804888e call realpath; 0x0804889e push "CWD"(0x08048a79)/push 1/call setenv@0x80485f0
> 
> **Source**: `ev-000002` · `ev-000001` · `ref:55b5536162`


## IOC (de-weaponized)

### Network

:::caution
**Pending dynamic verification**: the addresses above were obtained statically; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `172[.]245[.]80[.]41` | 80 | c2 | Static | ⏳ Not observed |

### Host

**Mutex**

- `/tmp/log_de.log (single-instance lock file; exits when present)`

**Drop paths**

- `/tmp/log_de.log`
- `memfd name "a" (exists only in process memory, no disk path)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `172[.]245[.]80[.]41` | Yes | Static |
| `c2_port` | `80` | Yes | Static |
| `stager_banner` | `"l32 " (6 bytes, sent first after connecting)` | Yes | Static |
| `stage_transport` | `Raw TCP; handshake = l32 magic + 2-byte port + 32-byte host string, followed by the downstream stage-two data stream` | Yes | Static |
| `encryption_algo` | `XOR 0x99 (single-byte repeating XOR, transport obfuscation only, not strong encryption)` | Yes | Static |
| `install_path` | `No disk install; stage two resides in an anonymous memfd (name "a")` | No | Static |
| `instance_lock_file` | `/tmp/log_de.log` | Yes | Static |
| `memfd_name` | `a` | Yes | Static |
| `process_masquerade` | `[kworker/0:2]` | No | Static |
| `reconnect_interval_sec` | `10` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not conclude it is ransomware or an info-stealer merely because it contains XOR decryption, downloading, and in-memory execution: the code has no file encryption, credential/browser data reads, or ransom-note logic.
- The second-stage payload was not obtained, so its concrete capabilities (whether it provides an interactive shell, whether it loads kernel/user-space hiding modules) cannot be asserted; only the "download—decrypt—execute in memory" delivery chain is confirmed.
- No writes to cron, systemd units, rc.local, or shell configuration files were found, so persistence capability cannot be asserted.
- The sample's callback target is a bare TCP port 80; the port number alone does not prove HTTP communication — the actual protocol is a custom handshake plus a raw data stream.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. Both execution attempts failed at the loader stage (missing /lib/ld-linux.so.2), never reached main, and produced no observable network/file behavior, so the c2 remains statically recovered and pending dynamic verification.
2. The second-stage payload is unknown; its hash, protocol, and subsequent capabilities cannot be given.
3. The family attribution is based on the handshake magic "l32 ", the memfd+fexecve loading pattern, and the source filename; it is a medium-confidence candidate and reuse of the stager by other families cannot be ruled out.
4. The network egress is isolated in the analysis environment, so whether the callback target is currently alive cannot be verified.

## Evidence index

<details>
<summary>Expand 9 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | String extraction: /tmp/log_de.log, l32 , CWD, [kworker/0:2], 172.245.80[.]41 (off 2656/2672/2681/2685/2700) |
| `ev-000002` | decompile.function | main@0x080486b0 decompilation: lock file, C2 connection, l32 handshake, recv+XOR 0x99, memfd_create, fexecve — the full chain |
| `ref:5ca1f4d12b` | disasm.function | main first half disassembly: access/exit, C2 string copy, port 0x5000, socket/setsockopt/connect/sleep |
| `ref:55b5536162` | disasm.function | main second half disassembly: send handshake, syscall 0x164, xor 0x99, realpath/setenv, fexecve |
| `ref:ce4b30f8fc` | static.bytes | rodata raw-byte verification: 0x08048a60=/tmp/log_de.log, 0x08048a70=l32 , 0x08048a77=a, 0x08048a79=CWD, 0x08048a7d=[kworker/0:2], 0x08048a8c=172.245.80[.]41 |
| `ref:1287bc8ab5` | ELF structure parsing | ELF32 i386 EXEC, entry 0x08048960, imports socket/connect/send/recv/gethostbyname/inet_addr/fexecve/realpath/setenv/syscall/access/sleep |
| `ref:523c01432d` | Hash and fingerprint | sha256 matches the provided description (6968 bytes), md5 f1b1df04e7b4259431bc3735ba79745a |
| `ev-000004` | dyn.exec | Isolated instance execution failed: strace exec ./prog returned ENOENT (missing 32-bit loader), the program never started |
| `ev-000005` | emu.qemu | User-mode emulation likewise refused to load for lack of /lib/ld-linux.so.2, exit=255 |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
